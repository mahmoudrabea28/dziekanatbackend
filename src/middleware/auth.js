const jwt = require('jsonwebtoken');
const User = require('../models/User');

function signAccess(user){
  return jwt.sign({sub: user._id, role: user.role}, process.env.JWT_SECRET, {expiresIn: Number(process.env.ACCESS_TOKEN_TTL || 900)});
}
function signRefresh(user){
  return jwt.sign({sub: user._id}, process.env.REFRESH_SECRET, {expiresIn: `${Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7)}d`});
}
async function auth(req,res,next){
  try{
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if(!token) return res.status(401).json({error:'Unauthorized'});
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(payload.sub);
    if(!req.user) return res.status(401).json({error:'Unauthorized'});
    next();
  }catch(err){ err.status=401; next(err); }
}
function hasRole(...roles){
  return (req,res,next)=>{
    if(!req.user) return res.status(401).json({error:'Unauthorized'});
    if(!roles.includes(req.user.role)) return res.status(403).json({error:'Forbidden'});
    next();
  };
}
async function issueTokens(res, user){
  const accessToken = signAccess(user);
  const refreshToken = signRefresh(user);
  user.refreshToken = refreshToken;
  await user.save();
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true, sameSite: 'lax', secure: (process.env.COOKIE_SECURE === 'true'),
    maxAge: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7)*24*60*60*1000
  });
  return accessToken;
}
module.exports = { auth, hasRole, issueTokens };
