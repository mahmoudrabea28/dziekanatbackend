const { Schema, model, Types } = require('mongoose');
const FileSchema = new Schema({ name:String, mime:String, size:Number, url:String, publicId:String }, {_id:false});
const ArticleSchema = new Schema({
  title:{type:String, required:true},
  authorsText:{type:String, default:''},
  files:{type:[FileSchema], default:[]},
  status:{type:String, enum:['submitted'], default:'submitted'},
  createdBy:{type:Types.ObjectId, ref:'User', required:true}
},{timestamps:true});
module.exports = model('Article', ArticleSchema);
