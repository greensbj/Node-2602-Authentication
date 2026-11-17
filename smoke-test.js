/**
 * End-to-end test of the whole auth flow.
 * Starts the app against MONGO_URI from .env, uses a throwaway test
 * database, walks every endpoint, then drops the database again.
 *
 *   node smoke-test.js
 */
process.env.NODE_ENV = 'test';
require('dotenv').config();

// Use a separate database so the demo data is never touched.
process.env.MONGO_URI = (process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/auth_demo')
  .replace(/\/[^/?]+(\?|$)/, '/auth_demo_test$1');

const mongoose = require('mongoose');
const app = require('./src/app');
const connectDB = require('./src/config/db');

(async () => {
  await connectDB();
  await mongoose.connection.dropDatabase();

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  let cookie = '';
  let accessToken = '';
  let pass = 0;
  let fail = 0;

  async function req(method, path, body, auth) {
    const headers = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(base + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    const json = await res.json().catch(() => ({}));
    if (json?.data?.accessToken) accessToken = json.data.accessToken;
    return { status: res.status, json };
  }

  function check(label, cond, extra) {
    if (cond) {
      pass += 1;
      console.log(`  PASS   ${label}`);
    } else {
      fail += 1;
      console.log(`  FAIL   ${label}`, extra ? JSON.stringify(extra) : '');
    }
  }

  console.log(`\nTesting against ${process.env.MONGO_URI}\n`);

  let r = await req('GET', '/api/health');
  check('health check responds', r.status === 200);

  r = await req('POST', '/api/auth/register', {
    name: 'Test User', email: 'test@example.com', password: 'Passw0rd123',
  });
  check('register returns 201 and an access token', r.status === 201 && !!accessToken, r.json);
  const verifyUrl = r.json?.data?.verifyUrl;
  const registeredOtp = r.json?.data?.otp;
  check('register issues an OTP', /^\d{6}$/.test(registeredOtp || ''), r.json?.data?.otp);

  r = await req('POST', '/api/auth/register', {
    name: 'Test User', email: 'test@example.com', password: 'Passw0rd123',
  });
  check('duplicate email rejected with 409', r.status === 409, r.json);

  r = await req('POST', '/api/auth/register', {
    name: 'X', email: 'not-an-email', password: 'weak',
  });
  check('invalid input rejected with 400 + field errors',
    r.status === 400 && r.json.errors?.length >= 2, r.json);

  r = await req('GET', '/api/auth/me', null, true);
  check('protected route works with a token',
    r.status === 200 && r.json.data.user.email === 'test@example.com');
  check('password hash never leaves the API', r.json?.data?.user?.password === undefined);

  r = await req('GET', '/api/auth/me');
  check('protected route rejects a missing token (401)', r.status === 401);

  r = await req('GET', '/api/users', null, true);
  check('admin route blocked for a normal user (403)', r.status === 403, r.json);

  // --- OTP verification ---------------------------------------------------
  r = await req('POST', '/api/auth/verify-otp', {
    email: 'test@example.com', otp: '000000',
  });
  const wrongRejected = r.status === 400;

  r = await req('POST', '/api/auth/verify-otp', {
    email: 'test@example.com', otp: 'abcdef',
  });
  check('OTP must be numeric (400)', r.status === 400, r.json);
  check('wrong OTP rejected (400)', wrongRejected);

  r = await req('POST', '/api/auth/send-otp', { email: 'test@example.com' });
  check('resend inside the cooldown is refused (429)', r.status === 429, r.json);

  r = await req('POST', '/api/auth/verify-otp', {
    email: 'test@example.com', otp: registeredOtp,
  });
  check('correct OTP verifies the account',
    r.status === 200 && r.json.data?.user?.isVerified === true, r.json);

  r = await req('POST', '/api/auth/verify-otp', {
    email: 'test@example.com', otp: registeredOtp,
  });
  check('OTP cannot be reused once verified (400)', r.status === 400, r.json);

  r = await req('POST', '/api/auth/send-otp', { email: 'nobody@example.com' });
  check('send-otp does not reveal unknown emails', r.status === 200, r.json);

  if (verifyUrl) {
    r = await req('GET', new URL(verifyUrl).pathname);
    check('verification link still resolves', r.status === 200 || r.status === 400, r.json);
  }

  r = await req('POST', '/api/auth/login', {
    email: 'test@example.com', password: 'WrongPass123',
  });
  check('wrong password rejected (401)', r.status === 401);

  r = await req('POST', '/api/auth/login', {
    email: 'test@example.com', password: 'Passw0rd123',
  });
  check('login succeeds with correct password',
    r.status === 200 && !!r.json.data.accessToken);

  const oldCookie = cookie;
  r = await req('POST', '/api/auth/refresh');
  check('refresh issues a new access token',
    r.status === 200 && !!r.json.data.accessToken);

  cookie = oldCookie;
  r = await req('POST', '/api/auth/refresh');
  check('replayed refresh token is detected and revoked (401)', r.status === 401, r.json);

  r = await req('POST', '/api/auth/login', {
    email: 'test@example.com', password: 'Passw0rd123',
  });
  check('can log in again after revocation', r.status === 200);

  r = await req('POST', '/api/auth/forgot-password', { email: 'test@example.com' });
  const resetToken = r.json?.data?.resetToken;
  check('forgot-password issues a reset token', r.status === 200 && !!resetToken);

  r = await req('PATCH', `/api/auth/reset-password/${resetToken}`, { password: 'Reset1234' });
  check('password reset succeeds', r.status === 200, r.json);

  r = await req('PATCH', `/api/auth/reset-password/${resetToken}`, { password: 'Reset1234' });
  check('reset token cannot be used twice (400)', r.status === 400);

  r = await req('POST', '/api/auth/login', {
    email: 'test@example.com', password: 'Reset1234',
  });
  check('login works with the new password', r.status === 200);

  r = await req('PATCH', '/api/auth/change-password', {
    currentPassword: 'Reset1234', newPassword: 'Changed123',
  }, true);
  check('change password succeeds', r.status === 200, r.json);

  r = await req('GET', '/api/auth/me', null, true);
  check('tokens issued before the change are rejected (401)', r.status === 401, r.json);

  r = await req('POST', '/api/auth/login', {
    email: 'nobody@example.com', password: 'Whatever123',
  });
  check('unknown email returns the same message as a wrong password',
    r.status === 401 && r.json.message === 'Invalid email or password');

  console.log(`\n  ${pass} passed, ${fail} failed\n`);

  await mongoose.connection.dropDatabase();
  server.close();
  await mongoose.disconnect();
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error('\nTest run failed:', err.message);
  console.error('Is MongoDB running? Try: brew services start mongodb-community\n');
  process.exit(1);
});
