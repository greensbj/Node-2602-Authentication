const rateLimit = require('express-rate-limit');
const { nodeEnv } = require('../config/env');

const common = {
  standardHeaders: true,
  legacyHeaders: false,
  // Automated test runs would otherwise trip the limiter.
  skip: () => nodeEnv === 'test',
  message: { success: false, message: 'Too many requests. Please try again later.' },
};

// Tight limit on the endpoints an attacker would brute-force.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  ...common,
});

// Looser limit for everything else.
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  ...common,
});

module.exports = { authLimiter, generalLimiter };
