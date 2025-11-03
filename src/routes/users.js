const router = require('express').Router();
const User = require('../models/User');
const Article = require('../models/Article');
const { auth } = require('../middleware/auth');
const { uploadAvatar, deleteFileSafe, saveBufferToLocal } = require('../utils/storage');
const { isCloudOn, uploadStream, deleteByPublicId } = require('../utils/cloud');

router.get('/me', auth, async (req,res)=>{ res.json(req.user) });

router.patch('/me', auth, uploadAvatar.single('avatar'), async (req,res,next)=>{
  try{
    const { firstName, lastName, phone, password } = req.body;
    if(firstName !== undefined) req.user.firstName = firstName;
    if(lastName !== undefined) req.user.lastName = lastName;
    if(phone !== undefined) req.user.phone = phone;
    if(password) await req.user.setPassword(password);

    if(req.file){
      if(isCloudOn()){
        const up = await uploadStream(req.file.buffer, req.file.originalname, (process.env.CLOUDINARY_FOLDER||'akademion')+'/avatars','image');
        if(req.user.avatarPublicId) await deleteByPublicId(req.user.avatarPublicId,'image'); else if(req.user.avatarUrl) deleteFileSafe(req.user.avatarUrl);
        req.user.avatarUrl = up.secure_url; req.user.avatarPublicId = up.public_id;
      }else{
        if(req.user.avatarPublicId) req.user.avatarPublicId=null;
        const url = saveBufferToLocal(req.file.buffer, req.file.originalname);
        if(req.user.avatarUrl) deleteFileSafe(req.user.avatarUrl);
        req.user.avatarUrl = url;
      }
    }

    await req.user.save();
    try{
      const fullName = `${req.user.firstName} ${req.user.lastName}`.trim();
      await Article.updateMany({ createdBy: req.user._id }, { $set: { authorName: fullName } });
      if(req.user.role === 'student'){
        await Article.updateMany({ mentorEmail: req.user.email }, { $set: { mentorName: fullName } });
      }
    }catch(_){}
    res.json(req.user);
  }catch(e){ next(e); }
});

router.get('/', async (req,res,next)=>{
  try{
    const { role } = req.query;
    const q = role ? { role } : {};
    const users = await User.find(q).select('_id email firstName lastName role avatarUrl');
    res.json(users);
  }catch(e){ next(e); }
});

module.exports = router;
