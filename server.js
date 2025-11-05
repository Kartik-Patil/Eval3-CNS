/**
 * Demo server: Captcha + OTP + SSL (self-signed for local)
 * - Uses svg-captcha for captcha generation
 * - Uses nodemailer to send OTP (configure SMTP)
 * - Uses HTTPS server with certificate files
 *
 * For demo only: OTPs stored in-memory and expire after short time.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const svgCaptcha = require('svg-captcha');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3443;

// === Security middlewares ===
app.use(helmet()); // add common security headers
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// simple session (for demo). Use secure store in production.
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_secret_for_prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,   // requires HTTPS
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000 // 10 min for demo
  }
}));

// Rate limiting on endpoints that can be abused
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // allow 10 requests per minute per IP for demo endpoints
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// === In-memory stores (demo only) ===
const otpStore = new Map(); // key: email, value: { otp, expiresAt, sessionId, attempts }

// === Configure nodemailer transporter ===
// For production, set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE (true/false)
let transporter;
async function createTransporter() {
  try {
    const hasSmtpEnv = !!process.env.SMTP_HOST;
    if (hasSmtpEnv) {
      const secureFlag = String(process.env.SMTP_SECURE).toLowerCase() === 'true';
      transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || (secureFlag ? 465 : 587),
        secure: secureFlag,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      // verify connection configuration
      try {
        await transporter.verify();
        console.log('Nodemailer transporter (SMTP) configured:', process.env.SMTP_HOST);
      } catch (vErr) {
        console.warn('Warning: could not verify SMTP transporter. Check credentials/network.', vErr && vErr.message ? vErr.message : vErr);
      }
    } else {
      // Ethereal fallback for dev/test only
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
      console.log('No SMTP config detected — using Ethereal test account for demo.');
    }
  } catch (err) {
    console.error('Failed to create mail transporter', err);
    throw err;
  }
}
createTransporter().catch(err => {
  console.error('Error creating transporter at startup:', err && err.message ? err.message : err);
});

// === Routes ===

// GET captcha image (SVG). Stores expected text in session.
app.get('/api/captcha', (req, res) => {
  const captcha = svgCaptcha.create({
    size: 6,
    noise: 2,
    ignoreChars: '0oO1ilI',
    color: false,
    background: '#ffffff'
  });
  req.session.captcha = captcha.text; // store text server-side in session
  res.type('svg');
  res.send(captcha.data);
});

// Request OTP (POST): expects { email, captcha }
app.post('/api/request-otp', async (req, res) => {
  try {
    const { email, captcha } = req.body;
    if (!email || !captcha) return res.status(400).json({ error: 'Missing email or captcha.' });

    // Validate captcha
    if (!req.session.captcha || captcha.toLowerCase() !== String(req.session.captcha).toLowerCase()) {
      return res.status(400).json({ error: 'Invalid captcha — try again.' });
    }

    // generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
    const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes
    const sessionId = uuidv4();

    otpStore.set(email, { otp, expiresAt, sessionId, attempts: 0 });

    // send email
    const mail = {
      from: process.env.EMAIL_FROM || process.env.SMTP_USER || 'no-reply@example.com',
      to: email,
      subject: 'Your demo OTP code',
      text: `Your OTP is: ${otp}. It expires in 5 minutes.`,
      html: `<p>Your OTP is: <strong>${otp}</strong>. It expires in 5 minutes.</p>`
    };

    if (!transporter) {
      // Attempt to (re)create transporter if startup failed earlier
      await createTransporter();
    }

    const info = await transporter.sendMail(mail);

    // For Ethereal or test accounts, nodemailer gives a preview URL
    let previewUrl = null;
    try {
      previewUrl = nodemailer.getTestMessageUrl(info) || null;
    } catch (e) {
      previewUrl = null;
    }

    // Logging
    console.log(`OTP mail attempted: to=${email} messageId=${info && info.messageId ? info.messageId : 'unknown'}`);
    if (previewUrl) console.log('Ethereal preview URL:', previewUrl);

    // remove used captcha (prevent replay)
    delete req.session.captcha;

    res.json({ ok: true, message: 'OTP sent (or simulated).', previewUrl });
  } catch (err) {
    console.error('Error in /api/request-otp:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'Failed to send OTP.' });
  }
});

// Verify OTP (POST): expects { email, otp }
app.post('/api/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields.' });

    const record = otpStore.get(email);
    if (!record) return res.status(400).json({ error: 'No OTP requested for this email.' });

    // Basic brute-force protection: allow limited attempts
    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts > 5) {
      otpStore.delete(email);
      return res.status(429).json({ error: 'Too many attempts. Request a new OTP.' });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    }

    if (otp !== record.otp) {
      return res.status(400).json({ error: 'Invalid OTP.' });
    }

    // success
    otpStore.delete(email);

    // create a demo authenticated session marker
    req.session.authenticated = true;
    req.session.userEmail = email;

    return res.json({ ok: true, message: 'OTP verified. You are authenticated for demo purposes.' });
  } catch (err) {
    console.error('Error in /api/verify-otp:', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Failed to verify OTP.' });
  }
});

// Protected demo route
app.get('/api/profile', (req, res) => {
  if (!req.session.authenticated) return res.status(401).json({ error: 'Not authenticated.' });
  res.json({ email: req.session.userEmail, message: 'Demo protected profile data.' });
});

// Simple logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// === HTTPS server setup ===
// Look for cert files in ./certs/server.key and ./certs/server.crt
const certDir = path.join(__dirname, 'certs');
const keyPath = path.join(certDir, 'server.key');
const certPath = path.join(certDir, 'server.crt');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  console.error('SSL certificate or key missing. Create a self-signed certificate and put server.key and server.crt into ./certs.');
  console.error('See README instructions in the project or the console message below for quick openssl command.');
  // For demo, still start HTTP fallback if desired (not recommended); here we exit to encourage HTTPS.
  process.exit(1);
}

const sslOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath)
};

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`HTTPS server running on https://localhost:${PORT}`);
});
