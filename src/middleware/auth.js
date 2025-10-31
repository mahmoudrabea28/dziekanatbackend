// src/routes/auth.js
const router = require('express').Router();
const User = require('../models/User');
const PendingUser = require('../models/PendingUser');
const { sendMail } = require('../utils/email');
const { issueTokens } = require('../middleware/auth');

function genCode(){ return ''+Math.floor(100000+Math.random()*900000); }

router.post('/register', async (req,res,next)=>{
  try{
    const { email, password, firstName, lastName, role } = req.body;
    if(!email || !password || !firstName || !lastName) return res.status(400).json({error:'Missing fields'});
    const allowed = ['professor','student']; 
    const r = allowed.includes(role) ? role : 'professor';

    const exists = await User.findOne({email});
    if(exists) return res.status(409).json({error:'Email already registered'});

    const code = genCode();
    await PendingUser.deleteOne({ email });
    await PendingUser.createFromPayload({ email, password, firstName, lastName, role: r, code });

    // ردّ بسرعة — ما تستناش SMTP
    res.status(201).json({ message: 'verification_sent' });

    // ابعت الإيميل في الخلفية (من غير await)
    setImmediate(() => {
      sendMail({
        to: email,
        subject: 'Dziekanat – Verify your email',
        html: `<p>Your verification code is <b>${code}</b>. It expires in 15 minutes.</p>`,
        text: `Your verification code is ${code}. It expires in 15 minutes.`
      }).catch(err => console.error('sendMail error:', err));
    });
  }catch(e){ next(e); }
});

// (اختياري لكنه مفيد) Resend code مع throttle بسيط
router.post('/resend-code', async (req,res,next)=>{
  try{
    const { email } = req.body;
    if(!email) return res.status(400).json({error:'Email required'});

    // امنع السبام: مرة كل دقيقة
    const key = `resend:${email}`;
    const last = req.app.get(key);
    if(last && Date.now() - last < 60_000) {
      return res.status(429).json({error:'Please wait a minute before resending.'});
    }
    req.app.set(key, Date.now());

    const pending = await PendingUser.findOne({email});
    if(!pending) return res.status(404).json({error:'No pending verification for this email'});

    const code = genCode();
    pending.code = code;
    pending.expiresAt = new Date(Date.now() + 15*60*1000);
    await pending.save();

    setImmediate(() => {
      sendMail({
        to: email,
        subject: 'Dziekanat – Verify your email',
        html: `<p>Your verification code is <b>${code}</b>. It expires in 15 minutes.</p>`,
        text: `Your verification code is ${code}. It expires in 15 minutes.`
      }).catch(err => console.error('sendMail error:', err));
    });

    res.json({ message: 'verification_resent' });
  }catch(e){ next(e); }
});
