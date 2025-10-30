const { Schema, model } = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: { type: String },
  role: { type: String, enum: ['professor','student'], default: 'professor' },
  avatarUrl: { type: String, default: null },
  avatarPublicId: { type: String, default: null },
  emailVerifiedAt: { type: Date, default: null },
  refreshToken: { type: String }
}, { timestamps: true });

UserSchema.methods.setPassword = async function(password){ this.passwordHash = await bcrypt.hash(password, 10); };
UserSchema.methods.verifyPassword = async function(password){ return bcrypt.compare(password, this.passwordHash); };
UserSchema.virtual('name').get(function(){ return `${this.firstName} ${this.lastName}`.trim(); });

module.exports = model('User', UserSchema);
