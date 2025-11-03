const cloudinary = require('cloudinary').v2;

function isCloudOn(){
  return !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
}
function configCloud(){
  if(!isCloudOn()) return;
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}
configCloud();

function uploadStream(buffer, filename, folder, resourceType='image'){
  if(!isCloudOn()) return Promise.resolve(null);
  const opts = {
    resource_type: resourceType,
    folder: folder || (process.env.CLOUDINARY_FOLDER || 'akademion'),
    use_filename: true,
    unique_filename: true,
    filename_override: filename
  };
  return new Promise((resolve, reject)=>{
    const stream = cloudinary.uploader.upload_stream(opts, (err, result)=>{
      if(err) reject(err); else resolve(result);
    });
    stream.end(buffer);
  });
}

async function deleteByPublicId(publicId, resourceType='image'){
  if(!isCloudOn() || !publicId) return;
  try{ await cloudinary.uploader.destroy(publicId, { resource_type: resourceType }); }catch(_){}
}

module.exports = { isCloudOn, uploadStream, deleteByPublicId };
