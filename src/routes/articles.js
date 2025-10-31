const router = require('express').Router();
const { auth, hasRole } = require('../middleware/auth');
const { uploadPdf, deleteFileSafe, saveBufferToLocal } = require('../utils/storage');
const Article = require('../models/Article');
const User = require('../models/User');
const { isCloudOn, uploadStream, deleteByPublicId } = require('../utils/cloud');

function parseKeywords(s){ if(Array.isArray(s)) return s; if(!s) return []; return String(s).split(',').map(x=>x.trim()).filter(Boolean); }
function buildFilter(q){
  const f = {};
  if(q.title) f.title = new RegExp(q.title,'i');
  if(q.scientificField) f.scientificField = new RegExp(q.scientificField,'i');
  if(q.status) f.status = q.status;
  if(q.keywords){ const arr = parseKeywords(q.keywords); if(arr.length) f.keywords = {$in:arr}; }
  if(q.q){ f.$or = [{title:new RegExp(q.q,'i')},{scientificField:new RegExp(q.q,'i')},{abstract:new RegExp(q.q,'i')},{keywords:{$in:[new RegExp(q.q,'i')]}}]; }
  return f;
}
async function mentorNameByEmail(email){
  if(!email) return null;
  const m = await User.findOne({ email: email.toLowerCase(), role:'student' }).lean();
  return m ? `${m.firstName} ${m.lastName}`.trim() : null;
}


router.post('/', auth, hasRole('professor'), uploadPdf.array('files',10), async (req,res,next)=>{
  try{
    const { title, authorsText = '' } = req.body;
    if(!title) return res.status(400).json({error:'Title is required'});
    if(!req.files || !req.files.length) return res.status(400).json({error:'A PDF file is required'});

    const files = [];
    for(const f of (req.files||[])){
      if(f.mimetype !== 'application/pdf'){
        return res.status(400).json({error:'Only PDF files are allowed'});
      }
      if(f.size > 10*1024*1024){
        return res.status(400).json({error:'PDF must be <= 10MB'});
      }
      if(isCloudOn()){
        const up = await uploadStream(f.buffer, f.originalname, (process.env.CLOUDINARY_FOLDER||'akademion')+'/articles','raw');
        files.push({ name:f.originalname, mime:f.mimetype, size:f.size, url: up.secure_url, publicId: up.public_id });
      }else{
        const url = saveBufferToLocal(f.buffer, f.originalname);
        files.push({ name:f.originalname, mime:f.mimetype, size:f.size, url });
      }
    }
    const professor = req.user;
    const article = await Article.create({
      title,
      authorsText,
      files,
      authors:[professor._id],
      authorName: `${professor.firstName} ${professor.lastName}`,
      createdBy: professor._id,
      status:'submitted'
    });
    res.status(201).json(article);
  }catch(e){ next(e); }
});

router.get('/', async (req,res,next)=>{
  try{ const arts = await Article.find(buildFilter(req.query)).sort('-createdAt'); res.json(arts); }
  catch(e){ next(e); }
});
router.get('/mine', auth, hasRole('professor'), async (req,res,next)=>{
  try{ const f = buildFilter(req.query); f.createdBy = req.user._id; const arts = await Article.find(f).sort('-createdAt'); res.json(arts); }
  catch(e){ next(e); }
});





router.get('/:id', async (req,res,next)=>{
  try{ const a = await Article.findById(req.params.id); if(!a) return res.status(404).json({error:'Not found'}); res.json(a); }
  catch(e){ next(e); }
});


router.patch('/:id', auth, hasRole('professor'), uploadPdf.array('files',10), async (req,res,next)=>{
  try{
    const a = await Article.findById(req.params.id);
    if(!a) return res.status(404).json({error:'Not found'});
    if(a.createdBy.toString() !== req.user._id.toString()) return res.status(403).json({error:'Forbidden'});
    if(a.status !== 'submitted' && a.status !== 'rejected') return res.status(400).json({error:'Only editable when status is submitted or rejected'});

    const { title, authorsText } = req.body;
    if(title !== undefined) a.title = title;
    if(authorsText !== undefined) a.authorsText = authorsText;

    const files = [];
    for(const f of (req.files||[])){
      if(f.mimetype !== 'application/pdf'){
        return res.status(400).json({error:'Only PDF files are allowed'});
      }
      if(f.size > 10*1024*1024){
        return res.status(400).json({error:'PDF must be <= 10MB'});
      }
      if(isCloudOn()){
        const up = await uploadStream(f.buffer, f.originalname, (process.env.CLOUDINARY_FOLDER||'akademion')+'/articles','raw');
        files.push({ name:f.originalname, mime:f.mimetype, size:f.size, url: up.secure_url, publicId: up.public_id });
      }else{
        const url = saveBufferToLocal(f.buffer, f.originalname);
        files.push({ name:f.originalname, mime:f.mimetype, size:f.size, url });
      }
    }
    if(files.length){
      (a.files||[]).forEach(f=>{ if(f.publicId) deleteByPublicId(f.publicId,'raw'); else deleteFileSafe(f.url) });
      a.files = files;
      a.publishedPdfUrl = undefined; // clear published override if replacing draft PDF
    }

    a.version = (a.version||0) + 1;
    await a.save();
    res.json(a);
  }catch(e){ next(e); }
});

router.delete('/:id', auth, hasRole('professor'), async (req,res,next)=>{
  try{
    const a = await Article.findById(req.params.id);
    if(!a) return res.status(404).json({error:'Not found'});
    if(a.createdBy.toString() !== req.user._id.toString()) return res.status(403).json({error:'Forbidden'});
    (a.files||[]).forEach(f=>{ if(f.publicId) deleteByPublicId(f.publicId,'raw'); else deleteFileSafe(f.url) });
    if(a.publishedPdfUrl){ if(/res\.cloudinary\.com/.test(a.publishedPdfUrl)){ /* if we want full cleanup, store publicId; skipped */ } else deleteFileSafe(a.publishedPdfUrl); }
    await a.deleteOne(); res.json({message:'deleted'});
  }catch(e){ next(e); }
});

module.exports = router;
