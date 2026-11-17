const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { saltRounds } = require('../config/env');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [60, 'Name cannot exceed 60 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    isVerified: {
      type: Boolean,
      default: false,
    },

    // Bumped whenever every existing access token must stop working
    // (password reset, password change, log out of all devices).
    // Compared exactly against the `tv` claim in the JWT, which avoids
    // the one-second resolution problem of a timestamp comparison.
    tokenVersion: {
      type: Number,
      default: 0,
    },

    // Hashed refresh tokens — one entry per active session/device.
    refreshTokens: [
      {
        tokenHash: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true },
      },
    ],

    verifyTokenHash: { type: String, select: false },
    verifyTokenExpires: { type: Date, select: false },

    // One-time passcode for email verification. Only the hash is stored,
    // exactly like the link tokens — a database leak must not reveal a
    // working code.
    otpHash: { type: String, select: false },
    otpExpires: { type: Date, select: false },
    otpAttempts: { type: Number, default: 0, select: false },
    otpLastSentAt: { type: Date, select: false },

    resetTokenHash: { type: String, select: false },
    resetTokenExpires: { type: Date, select: false },

    passwordChangedAt: { type: Date, select: false },

    loginAttempts: { type: Number, default: 0, select: false },
    lockUntil: { type: Date, select: false },
  },
  {
    timestamps: true,
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        delete ret.refreshTokens;
        delete ret.verifyTokenHash;
        delete ret.verifyTokenExpires;
        delete ret.resetTokenHash;
        delete ret.resetTokenExpires;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordChangedAt;
        delete ret.tokenVersion;
        delete ret.otpHash;
        delete ret.otpExpires;
        delete ret.otpAttempts;
        delete ret.otpLastSentAt;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// --- Hash the password whenever it is set or changed -----------------------
userSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, saltRounds);
  if (!this.isNew) this.passwordChangedAt = new Date();

  return next();
});

// --- Instance methods ------------------------------------------------------
userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.isLocked = function isLocked() {
  return Boolean(this.lockUntil && this.lockUntil > Date.now());
};

/**
 * Creates a random token, stores only its SHA-256 hash on the document,
 * and returns the plain token for emailing / displaying once.
 */
userSchema.methods.createOneTimeToken = function createOneTimeToken(kind, ttlMs) {
  const plain = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(plain).digest('hex');

  if (kind === 'verify') {
    this.verifyTokenHash = hash;
    this.verifyTokenExpires = new Date(Date.now() + ttlMs);
  } else {
    this.resetTokenHash = hash;
    this.resetTokenExpires = new Date(Date.now() + ttlMs);
  }

  return plain;
};

userSchema.statics.hashToken = function hashToken(plain) {
  return crypto.createHash('sha256').update(plain).digest('hex');
};

/**
 * Generates a numeric one-time passcode, stores only its hash, and
 * returns the plain code so it can be sent to the user once.
 * crypto.randomInt is used rather than Math.random: the code must not be
 * predictable from previously issued ones.
 */
userSchema.methods.createOtp = function createOtp(length, ttlMs) {
  const max = 10 ** length;
  const code = String(crypto.randomInt(0, max)).padStart(length, '0');

  this.otpHash = crypto.createHash('sha256').update(code).digest('hex');
  this.otpExpires = new Date(Date.now() + ttlMs);
  this.otpAttempts = 0;
  this.otpLastSentAt = new Date();

  return code;
};

userSchema.methods.clearOtp = function clearOtp() {
  this.otpHash = undefined;
  this.otpExpires = undefined;
  this.otpAttempts = 0;
};

module.exports = mongoose.model('User', userSchema);
