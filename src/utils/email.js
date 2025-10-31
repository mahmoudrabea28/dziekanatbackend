const nodemailer = require('nodemailer');

// Use a pooled transporter with sensible timeouts to avoid long blocking awaits on free hosts
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  pool: true,
  maxConnections: 2,
  maxMessages: 100,
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
});

/**
 * Fire-and-forget email sending to prevent request timeouts on providers like Render free tier.
 * Callers can `await sendMail(...)` safely—this function resolves immediately after queuing.
 */
async function sendMail({ to, subject, html, text }) {
  if (!process.env.SMTP_USER) {
    console.log('SMTP not configured; logging email:', { to, subject, text });
    return;
  }
  // Queue send without awaiting, and swallow errors to avoid breaking HTTP response
  transporter
    .sendMail({
      from: process.env.MAIL_FROM || 'no-reply@akademion.local',
      to,
      subject,
      html,
      text,
    })
    .then(info => {
      console.log('Email queued:', info && info.messageId ? info.messageId : 'ok');
    })
    .catch(err => {
      console.error('Email error:', err && err.message ? err.message : err);
    });
  // Resolve immediately
  return;
}

module.exports = { sendMail };
