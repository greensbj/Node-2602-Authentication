const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { jwt: jwtCfg, nodeEnv } = require('../config/env');

const REFRESH_COOKIE = 'refreshToken';

function signAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, tv: user.tokenVersion },
    jwtCfg.accessSecret,
    { expiresIn: jwtCfg.accessExpires }
  );
}

function signRefreshToken(user) {
  // jti lets us revoke a single session without touching the others.
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user._id.toString(), jti },
    jwtCfg.refreshSecret,
    { expiresIn: jwtCfg.refreshExpires }
  );
  return { token, jti };
}

function verifyAccessToken(token) {
  return jwt.verify(token, jwtCfg.accessSecret);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, jwtCfg.refreshSecret);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function setRefreshCookie(res, token) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: nodeEnv === 'production',
    sameSite: 'strict',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, { path: '/api/auth' });
}

module.exports = {
  REFRESH_COOKIE,
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken,
  setRefreshCookie,
  clearRefreshCookie,
};
