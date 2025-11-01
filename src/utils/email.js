const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendMail({to, subject, html, text}){
  if(!process.env.SMTP_USER){
    console.log('SMTP not configured; logging email:', {to, subject, text});
    return;
  }
  await transporter.sendMail({ from: process.env.MAIL_FROM || 'no-reply@akademion.local', to, subject, html, text });
}
module.exports = { sendMail };
