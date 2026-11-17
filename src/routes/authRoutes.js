const express = require('express');
const ctrl = require('../controllers/authController');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const rules = require('../validators/authValidators');

const router = express.Router();

// --- Public ----------------------------------------------------------------
router.post('/register', authLimiter, rules.registerRules, validate, ctrl.register);
router.post('/login', authLimiter, rules.loginRules, validate, ctrl.login);
router.post('/refresh', ctrl.refresh);
router.post('/logout', ctrl.logout);

router.get('/verify-email/:token', ctrl.verifyEmail);
router.post('/send-otp', authLimiter, rules.sendOtpRules, validate, ctrl.sendOtp);
router.post('/verify-otp', authLimiter, rules.verifyOtpRules, validate, ctrl.verifyOtp);
router.post('/forgot-password', authLimiter, rules.forgotRules, validate, ctrl.forgotPassword);
router.patch('/reset-password/:token', authLimiter, rules.resetRules, validate, ctrl.resetPassword);

// --- Protected -------------------------------------------------------------
router.get('/me', protect, ctrl.me);
router.post('/logout-all', protect, ctrl.logoutAll);
router.patch('/change-password', protect, rules.changePasswordRules, validate, ctrl.changePassword);

module.exports = router;
