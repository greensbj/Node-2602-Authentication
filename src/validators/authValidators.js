const { body } = require('express-validator');

const passwordRule = (field = 'password') =>
  body(field)
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[a-z]/)
    .withMessage('Password must contain a lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain an uppercase letter')
    .matches(/\d/)
    .withMessage('Password must contain a number');

const emailRule = body('email')
  .trim()
  .isEmail()
  .withMessage('Please provide a valid email')
  .normalizeEmail();

exports.registerRules = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 60 })
    .withMessage('Name must be between 2 and 60 characters'),
  emailRule,
  passwordRule(),
];

exports.loginRules = [
  emailRule,
  body('password').notEmpty().withMessage('Password is required'),
];

exports.forgotRules = [emailRule];

exports.sendOtpRules = [emailRule];

exports.verifyOtpRules = [
  emailRule,
  body('otp')
    .trim()
    .isLength({ min: 4, max: 8 })
    .withMessage('Code must be between 4 and 8 digits')
    .isNumeric()
    .withMessage('Code must contain digits only'),
];

exports.resetRules = [passwordRule()];

exports.changePasswordRules = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  passwordRule('newPassword'),
  body('newPassword').custom((value, { req }) => {
    if (value === req.body.currentPassword) {
      throw new Error('New password must be different from the current one');
    }
    return true;
  }),
];
