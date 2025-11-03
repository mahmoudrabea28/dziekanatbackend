const mongoose = require('mongoose');
module.exports = async function connect(){
  const uri = process.env.MONGODB_URI;
  if(!uri) throw new Error('MONGODB_URI missing');
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri);
  console.log('MongoDB connected');
}
