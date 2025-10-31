// Fallback: Resend -> SMTP -> MOCK
const nodemailer = require('nodemailer');

async function sendViaSMTP({ to, subject, html, text }) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
  });
  await transporter.sendMail({
    from: process.env.MAIL_FROM || 'Dziekanat <no-reply@dz.local>',
    to, subject, html, text,
  });
}

async function sendViaResend({ to, subject, html, text }) {
  const { Resend } = require('resend');
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: process.env.MAIL_FROM || 'Dziekanat <onboarding@resend.dev>',
    to, subject, html, text,
  });
}

async function sendMail(payload) {
  if (process.env.EMAIL_MOCK === '1') {
    console.log('MOCK EMAIL >>>', payload);
    return { mocked: true };
  }
  try {
    if (process.env.RESEND_API_KEY) return await sendViaResend(payload);
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) return await sendViaSMTP(payload);
    console.log('MOCK EMAIL (no provider) >>>', payload);
    return { mocked: true };
  } catch (e) {
    console.error('sendMail failed:', e.message || e);
    console.log('MOCK EMAIL (fallback) >>>', payload);
    return { mocked: true, error: e.message || String(e) };
  }
}

module.exports = { sendMail };
