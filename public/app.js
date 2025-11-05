// public/app.js
// Handles captcha refresh, request-otp, verify-otp and profile fetch.
// Note: fetch uses credentials:'same-origin' to send the session cookie.

document.addEventListener('DOMContentLoaded', () => {
  const captchaImg = document.getElementById('captchaImg');
  const refreshBtn = document.getElementById('refreshCaptcha');
  const sendOtpBtn = document.getElementById('sendOtp');
  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  const getProfileBtn = document.getElementById('getProfile');

  refreshBtn.addEventListener('click', () =>
    captchaImg.src = '/api/captcha?' + Date.now()
  );

  sendOtpBtn.addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    const captcha = document.getElementById('captchaInput').value;
    const msgEl = document.getElementById('otpMessage');
    msgEl.style.display = 'none';
    try {
      const res = await fetch('/api/request-otp', {
        method: 'POST',
        credentials: 'same-origin',               // send session cookie
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ email, captcha })
      });
      const json = await res.json();
      console.log('/api/request-otp response', res.status, json);
      msgEl.style.display = 'block';
      if (json.ok) {
        msgEl.textContent = json.message + (json.previewUrl ? ' Preview: ' + json.previewUrl : '');
      } else {
        msgEl.textContent = 'Error: ' + (json.error || 'unknown');
      }
      // refresh captcha after request to avoid reuse
      captchaImg.src = '/api/captcha?' + Date.now();
    } catch (e) {
      console.error('request-otp failed', e);
      msgEl.style.display = 'block';
      msgEl.textContent = 'Network error';
    }
  });

  verifyOtpBtn.addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    const otp = document.getElementById('otpField').value;
    const msg = document.getElementById('verifyMessage');
    msg.style.display = 'none';
    try {
      const res = await fetch('/api/verify-otp', {
        method: 'POST',
        credentials: 'same-origin',               // send session cookie
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ email, otp })
      });
      const json = await res.json();
      console.log('/api/verify-otp response', res.status, json);
      msg.style.display = 'block';
      if (json.ok) {
        msg.textContent = json.message;
      } else {
        msg.textContent = 'Error: ' + (json.error || 'unknown');
      }
    } catch (e) {
      console.error('verify-otp failed', e);
      msg.style.display = 'block';
      msg.textContent = 'Network error';
    }
  });

  getProfileBtn.addEventListener('click', async () => {
    const p = document.getElementById('profile');
    p.style.display = 'none';
    try {
      const res = await fetch('/api/profile', { credentials: 'same-origin' });
      const json = await res.json();
      console.log('/api/profile response', res.status, json);
      p.style.display = 'block';
      if (res.ok) p.textContent = JSON.stringify(json);
      else p.textContent = 'Error: ' + (json.error || 'unknown');
    } catch (e) {
      console.error('get profile failed', e);
      p.style.display = 'block';
      p.textContent = 'Network error';
    }
  });
});
