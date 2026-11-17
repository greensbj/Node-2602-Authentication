const crypto = require('crypto');
const User = require('../models/User');
const ApiError = require('../utils/ApiError');
const asyncHandler = require('../utils/asyncHandler');
const {
  clientUrl,
  nodeEnv,
  maxLoginAttempts,
  lockTimeMs,
  resetTtlMs,
  verifyTtlMs,
  otp: otpCfg,
} = require('../config/env');
const {
  REFRESH_COOKIE,
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashToken,
  setRefreshCookie,
  clearRefreshCookie,
} = require('../utils/token');

const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Issues a new access + refresh pair and records the refresh hash. */
async function issueTokens(user, res) {
  const accessToken = signAccessToken(user);
  const { token: refreshToken } = signRefreshToken(user);

  user.refreshTokens.push({
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
  });

  // Drop expired sessions and cap the list so it cannot grow forever.
  user.refreshTokens = user.refreshTokens
    .filter((t) => t.expiresAt > Date.now())
    .slice(-5);

  await user.save({ validateBeforeSave: false });
  setRefreshCookie(res, refreshToken);

  return accessToken;
}

// POST /api/auth/register
exports.register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (await User.exists({ email })) {
    throw ApiError.conflict('That email is already registered');
  }

  const user = new User({ name, email, password });
  const verifyToken = user.createOneTimeToken('verify', verifyTtlMs);
  const otp = user.createOtp(otpCfg.length, otpCfg.ttlMs);
  await user.save();

  // eslint-disable-next-line no-console
  console.log(`\n[OTP for ${email}] ${otp}  (valid ${otpCfg.ttlMs / 1000}s)\n`);

  const verifyUrl = `${clientUrl}/api/auth/verify-email/${verifyToken}`;
  // In a real app this would be emailed. For the demo it is logged and,
  // outside production, returned so you can click straight through.
  // eslint-disable-next-line no-console
  console.log(`\n[verify email] ${verifyUrl}\n`);

  const accessToken = await issueTokens(user, res);

  res.status(201).json({
    success: true,
    message: 'Registered successfully',
    data: {
      user,
      accessToken,
      ...(nodeEnv !== 'production' ? { verifyUrl, otp } : {}),
    },
  });
});

// POST /api/auth/send-otp     { email }
exports.sendOtp = asyncHandler(async (req, res) => {
  const user = await User.findOne({ email: req.body.email }).select(
    '+otpHash +otpExpires +otpAttempts +otpLastSentAt'
  );

  const reply = {
    success: true,
    message: 'If that email is registered, a code has been sent',
  };

  if (!user) return res.json(reply);

  if (user.isVerified) {
    throw ApiError.badRequest('This account is already verified');
  }

  // Cooldown stops the endpoint being used to spam someone's inbox.
  if (user.otpLastSentAt) {
    const since = Date.now() - user.otpLastSentAt.getTime();
    if (since < otpCfg.resendCooldownMs) {
      const wait = Math.ceil((otpCfg.resendCooldownMs - since) / 1000);
      throw ApiError.tooMany(`Please wait ${wait}s before requesting another code`);
    }
  }

  const otp = user.createOtp(otpCfg.length, otpCfg.ttlMs);
  await user.save({ validateBeforeSave: false });

  // eslint-disable-next-line no-console
  console.log(`\n[OTP for ${user.email}] ${otp}  (valid ${otpCfg.ttlMs / 1000}s)\n`);

  return res.json({
    ...reply,
    ...(nodeEnv !== 'production'
      ? { data: { otp, expiresInSeconds: otpCfg.ttlMs / 1000 } }
      : {}),
  });
});

// POST /api/auth/verify-otp   { email, otp }
exports.verifyOtp = asyncHandler(async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email }).select(
    '+otpHash +otpExpires +otpAttempts'
  );

  // One message for every failure mode, so the endpoint cannot be used
  // to work out which emails exist or which codes are close.
  const invalid = () => ApiError.badRequest('Invalid or expired code');

  if (!user || !user.otpHash) throw invalid();

  if (user.isVerified) {
    throw ApiError.badRequest('This account is already verified');
  }

  if (user.otpExpires < Date.now()) {
    user.clearOtp();
    await user.save({ validateBeforeSave: false });
    throw invalid();
  }

  // Guessing a 6-digit code is only hard if guesses are capped.
  if (user.otpAttempts >= otpCfg.maxAttempts) {
    user.clearOtp();
    await user.save({ validateBeforeSave: false });
    throw ApiError.tooMany('Too many incorrect attempts. Request a new code');
  }

  const presented = User.hashToken(String(otp));

  // Constant-time compare: both sides are fixed-length hex digests.
  const ok = crypto.timingSafeEqual(
    Buffer.from(presented, 'hex'),
    Buffer.from(user.otpHash, 'hex')
  );

  if (!ok) {
    user.otpAttempts += 1;
    await user.save({ validateBeforeSave: false });
    const left = Math.max(0, otpCfg.maxAttempts - user.otpAttempts);
    throw ApiError.badRequest(`Invalid or expired code. ${left} attempt(s) left`);
  }

  user.isVerified = true;
  user.clearOtp();
  user.verifyTokenHash = undefined;
  user.verifyTokenExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.json({ success: true, message: 'Email verified successfully', data: { user } });
});

// POST /api/auth/login
exports.login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select(
    '+password +loginAttempts +lockUntil'
  );

  // Same message either way, so the response cannot be used to
  // discover which emails exist.
  if (!user) throw ApiError.unauthorized('Invalid email or password');

  if (user.isLocked()) {
    const ms = user.lockUntil - Date.now();
    const wait = ms < 60000
      ? `${Math.ceil(ms / 1000)} second(s)`
      : `${Math.ceil(ms / 60000)} minute(s)`;
    throw ApiError.tooMany(`Account locked. Try again in ${wait}`);
  }

  const match = await user.comparePassword(password);

  if (!match) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= maxLoginAttempts) {
      user.lockUntil = new Date(Date.now() + lockTimeMs);
      user.loginAttempts = 0;
    }
    await user.save({ validateBeforeSave: false });
    throw ApiError.unauthorized('Invalid email or password');
  }

  user.loginAttempts = 0;
  user.lockUntil = undefined;

  const accessToken = await issueTokens(user, res);

  res.json({
    success: true,
    message: 'Logged in successfully',
    data: { user, accessToken },
  });
});

// POST /api/auth/refresh
exports.refresh = asyncHandler(async (req, res) => {
  const token = req.cookies?.[REFRESH_COOKIE] || req.body.refreshToken;
  if (!token) throw ApiError.unauthorized('No refresh token provided');

  let payload;
  try {
    payload = verifyRefreshToken(token);
  } catch {
    clearRefreshCookie(res);
    throw ApiError.unauthorized('Invalid or expired refresh token');
  }

  const user = await User.findById(payload.sub);
  if (!user) throw ApiError.unauthorized('User no longer exists');

  const presented = hashToken(token);
  const stored = user.refreshTokens.find((t) => t.tokenHash === presented);

  if (!stored) {
    // The token is validly signed but is not on file: it was already
    // rotated or revoked. Treat it as replay and kill every session.
    user.refreshTokens = [];
    await user.save({ validateBeforeSave: false });
    clearRefreshCookie(res);
    throw ApiError.unauthorized('Refresh token reuse detected. Please log in again');
  }

  // Rotation: the old token is discarded as the new one is issued.
  user.refreshTokens = user.refreshTokens.filter((t) => t.tokenHash !== presented);
  const accessToken = await issueTokens(user, res);

  res.json({
    success: true,
    message: 'Token refreshed',
    data: { accessToken },
  });
});

// POST /api/auth/logout
exports.logout = asyncHandler(async (req, res) => {
  const token = req.cookies?.[REFRESH_COOKIE] || req.body.refreshToken;

  if (token) {
    const presented = hashToken(token);
    await User.updateOne(
      { 'refreshTokens.tokenHash': presented },
      { $pull: { refreshTokens: { tokenHash: presented } } }
    );
  }

  clearRefreshCookie(res);
  res.json({ success: true, message: 'Logged out successfully' });
});

// POST /api/auth/logout-all   (protected)
exports.logoutAll = asyncHandler(async (req, res) => {
  req.user.refreshTokens = [];
  req.user.tokenVersion += 1; // retires outstanding access tokens too
  await req.user.save({ validateBeforeSave: false });
  clearRefreshCookie(res);
  res.json({ success: true, message: 'Logged out of all devices' });
});

// GET /api/auth/me   (protected)
exports.me = asyncHandler(async (req, res) => {
  res.json({ success: true, data: { user: req.user } });
});

// GET /api/auth/verify-email/:token
exports.verifyEmail = asyncHandler(async (req, res) => {
  const tokenHash = User.hashToken(req.params.token);

  const user = await User.findOne({
    verifyTokenHash: tokenHash,
    verifyTokenExpires: { $gt: Date.now() },
  }).select('+verifyTokenHash +verifyTokenExpires');

  if (!user) throw ApiError.badRequest('Verification link is invalid or has expired');

  user.isVerified = true;
  user.verifyTokenHash = undefined;
  user.verifyTokenExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.json({ success: true, message: 'Email verified successfully' });
});

// POST /api/auth/forgot-password
exports.forgotPassword = asyncHandler(async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  // Always the same reply, so the endpoint cannot enumerate accounts.
  const reply = {
    success: true,
    message: 'If that email is registered, a reset link has been sent',
  };

  if (!user) return res.json(reply);

  const resetToken = user.createOneTimeToken('reset', resetTtlMs);
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${clientUrl}/reset-password/${resetToken}`;
  // eslint-disable-next-line no-console
  console.log(`\n[reset password] ${resetUrl}\n`);

  return res.json({
    ...reply,
    ...(nodeEnv !== 'production' ? { data: { resetUrl, resetToken } } : {}),
  });
});

// PATCH /api/auth/reset-password/:token
exports.resetPassword = asyncHandler(async (req, res) => {
  const tokenHash = User.hashToken(req.params.token);

  const user = await User.findOne({
    resetTokenHash: tokenHash,
    resetTokenExpires: { $gt: Date.now() },
  }).select('+resetTokenHash +resetTokenExpires');

  if (!user) throw ApiError.badRequest('Reset link is invalid or has expired');

  user.password = req.body.password;
  user.resetTokenHash = undefined;
  user.resetTokenExpires = undefined;
  user.refreshTokens = []; // force every device to log in again
  user.tokenVersion += 1; // and retire any access token still in flight
  user.loginAttempts = 0;
  user.lockUntil = undefined;
  await user.save();

  clearRefreshCookie(res);
  res.json({ success: true, message: 'Password reset. Please log in again' });
});

// PATCH /api/auth/change-password   (protected)
exports.changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user._id).select('+password');
  if (!(await user.comparePassword(currentPassword))) {
    throw ApiError.unauthorized('Current password is incorrect');
  }

  user.password = newPassword;
  user.refreshTokens = [];
  user.tokenVersion += 1;
  await user.save();

  clearRefreshCookie(res);
  res.json({ success: true, message: 'Password changed. Please log in again' });
});
