require('dotenv').config();

const required = ['MONGO_URI', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET'];

for (const key of required) {
  if (!process.env[key]) {
    // eslint-disable-next-line no-console
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const num = (value, fallback) => (value === undefined ? fallback : Number(value));

module.exports = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: num(process.env.PORT, 5000),
  mongoUri: process.env.MONGO_URI,
  clientUrl: process.env.CLIENT_URL || 'http://localhost:5000',
  saltRounds: num(process.env.BCRYPT_SALT_ROUNDS, 10),

  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpires: process.env.JWT_ACCESS_EXPIRES || '15m',
    refreshExpires: process.env.JWT_REFRESH_EXPIRES || '7d',
  },

  // Security timings, in milliseconds. Short values in the demo .env so the
  // lockout and OTP expiry can be shown without waiting around.
  maxLoginAttempts: num(process.env.MAX_LOGIN_ATTEMPTS, 5),
  lockTimeMs: num(process.env.LOCK_TIME_MS, 15 * 60 * 1000),
  resetTtlMs: num(process.env.RESET_TOKEN_TTL_MS, 15 * 60 * 1000),
  verifyTtlMs: num(process.env.VERIFY_TOKEN_TTL_MS, 24 * 60 * 60 * 1000),

  otp: {
    length: num(process.env.OTP_LENGTH, 6),
    ttlMs: num(process.env.OTP_TTL_MS, 5 * 60 * 1000),
    maxAttempts: num(process.env.OTP_MAX_ATTEMPTS, 5),
    resendCooldownMs: num(process.env.OTP_RESEND_COOLDOWN_MS, 60 * 1000),
  },
};
