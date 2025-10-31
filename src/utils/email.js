// src/utils/email.js
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true', // 465 = true, 587/25 = false
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  pool: true,
  maxConnections: 1,
  maxMessages: 100,
  connectionTimeout: 15000,
  socketTimeout: 15000,
});

async function sendMail({ to, subject, html, text }){
  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  return transporter.sendMail({ from, to, subject, html, text });
}

module.exports = { sendMail };
