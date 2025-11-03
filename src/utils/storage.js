const multer = require('multer');
const path = require('path'); const fs = require('fs');
const uploadRoot = path.join(__dirname, '..', 'uploads');
if(!fs.existsSync(uploadRoot)) fs.mkdirSync(uploadRoot, {recursive:true});

const memory = multer.memoryStorage();

function saveBufferToLocal(buffer, originalname){
  const ext = path.extname(originalname) || '';
  const name = Date.now()+'-'+Math.round(Math.random()*1e9)+ext;
  const full = path.join(uploadRoot, name);
  fs.writeFileSync(full, buffer);
  return '/uploads/' + name;
}
function deleteFileSafe(p){
  try{
    if(!p) return;
    const full = p.startsWith('/uploads/') ? path.join(__dirname,'..',p) : p;
    if(full.startsWith(uploadRoot) && fs.existsSync(full)) fs.unlinkSync(full);
  }catch(_){}
}

const MAX_AVATAR_SIZE = 2 * 1024 * 1024;  // 2MB
const MAX_PDF_SIZE = 10 * 1024 * 1024;    // 10MB

const uploadAvatar = multer({
  storage: memory,
  limits: { fileSize: MAX_AVATAR_SIZE },
  fileFilter: (req,file,cb)=>{ const ok = /^image\//.test(file.mimetype); cb(ok?null:new Error('Only image files allowed for avatar'), ok); }
});
const uploadPdf = multer({
  storage: memory,
  limits: { fileSize: MAX_PDF_SIZE },
  fileFilter: (req,file,cb)=>{ const ok = file.mimetype === 'application/pdf' || /\.pdf$/i.test(file.originalname); cb(ok?null:new Error('Only PDF files are allowed'), ok); }
});

module.exports = { uploadAvatar, uploadPdf, saveBufferToLocal, deleteFileSafe };
