const router = require('express').Router();
const User = require('../models/User');
const PendingUser = require('../models/PendingUser');
const { sendMail } = require('../utils/email');
const { issueTokens } = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');


function genCode(){ return ''+Math.floor(100000+Math.random()*900000); }

router.post('/register', async (req,res,next)=>{
  try{
    const { email, password, firstName, lastName, role } = req.body;
    if(!email || !password || !firstName || !lastName) return res.status(400).json({error:'Missing fields'});
    const allowed = ['professor','student']; const r = allowed.includes(role) ? role : 'professor';
    const exists = await User.findOne({email}); if(exists) return res.status(409).json({error:'Email already registered'});
    const code = genCode(); await PendingUser.deleteOne({email}); await PendingUser.createFromPayload({email,password,firstName,lastName,role:r,code});
    await sendMail({ to:email, subject:'Akademion - Verify your email', text:`Your verification code is ${code}. It expires in 15 minutes.` });
    res.status(201).json({ message:'verification_sent' });
  }catch(e){ next(e); }
});

router.post('/verify-email', async (req,res,next)=>{
  try{
    const { email, code } = req.body;
    const pending = await PendingUser.findOne({email});
    if(!pending) return res.status(404).json({error:'No pending verification for this email'});
    if(pending.code !== code || pending.expiresAt < new Date()) return res.status(400).json({error:'Invalid or expired code'});
    let user = await User.findOne({email});
    if(!user){
      user = new User({ email, passwordHash: pending.passwordHash, firstName: pending.firstName, lastName: pending.lastName, role: pending.role, emailVerifiedAt: new Date() });
      await user.save();
    }
    await PendingUser.deleteOne({email});
    const accessToken = await issueTokens(res, user);
    res.json({ message:'verified', accessToken, user });
  }catch(e){ next(e); }
});

router.post('/login', async (req,res,next)=>{
  try{
    const { email, password, rememberMe } = req.body;
    const user = await User.findOne({email});
    if(!user) return res.status(401).json({error:'Invalid credentials'});
    const ok = await user.verifyPassword(password);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    const accessToken = await issueTokens(res, user, !!rememberMe);
    res.json({ accessToken, user });
  }catch(e){ next(e); }
});

router.post('/refresh', async (req,res,next)=>{
  try{
    const token = req.cookies.refreshToken;
    if(!token) return res.status(401).json({error:'No refresh token'});
    const payload = jwt.verify(token, process.env.REFRESH_SECRET);
    const user = await User.findById(payload.sub);
    if(!user || user.refreshToken !== token) return res.status(401).json({error:'Invalid refresh token'});
    const accessToken = await issueTokens(res, user, true);
    res.json({ accessToken });
  }catch(e){ next(e); }
});


// Google Sign-In (ID token) endpoint
router.post('/google', async (req,res,next)=>{
  try{
    const { credential } = req.body || {};
    if(!credential) return res.status(400).json({error:'Missing credential'});
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload?.email;
    const emailVerified = payload?.email_verified;
    const googleId = payload?.sub;
    if(!email || !emailVerified) return res.status(400).json({error:'Unverified Google account'});
    let user = await User.findOne({ email });
    if(!user){
      const firstName = payload?.given_name || (email.split('@')[0]||'').slice(0,30);
      const lastName = payload?.family_name || '';
      const randomPass = crypto.randomBytes(24).toString('hex');
      const passwordHash = await bcrypt.hash(randomPass, 10);
      user = new User({
        email, passwordHash, firstName, lastName,
        role: 'student', provider:'google', googleId, emailVerifiedAt: new Date()
      });
      await user.save();
    }else{
      // Upgrade existing local user if needed
      let changed=false;
      if(!user.emailVerifiedAt){ user.emailVerifiedAt = new Date(); changed=true; }
      if(!user.provider){ user.provider='google'; changed=true; }
      if(!user.googleId){ user.googleId=googleId; changed=true; }
      if(changed) await user.save();
    }
    const accessToken = await issueTokens(res, user);
    res.json({ accessToken, user });
  }catch(e){ next(e); }
});

router.post('/logout', async (req,res,next)=>{
  try{
    const token = req.cookies.refreshToken;
    if(token){
      try{ const payload = jwt.verify(token, process.env.REFRESH_SECRET); const user = await User.findById(payload.sub); if(user){ user.refreshToken = null; await user.save(); } }catch(_){}
    }
    res.clearCookie('refreshToken');
    res.json({ message:'logged_out' });
  }catch(e){ next(e); }
});

module.exports = router;
