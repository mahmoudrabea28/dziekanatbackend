const { Schema, model } = require('mongoose');
const bcrypt = require('bcryptjs');

const PendingUserSchema = new Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['professor','student'], default: 'professor' },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true }
}, { timestamps: true });

PendingUserSchema.statics.createFromPayload = async function({email,password,firstName,lastName,role,code,ttlMinutes=15}){
  const passwordHash = await bcrypt.hash(password, 10);
  const expiresAt = new Date(Date.now() + ttlMinutes*60*1000);
  return this.create({ email, passwordHash, firstName, lastName, role, code, expiresAt });
};

module.exports = model('PendingUser', PendingUserSchema);
