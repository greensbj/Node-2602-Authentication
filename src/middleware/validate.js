const { validationResult } = require('express-validator');
const ApiError = require('../utils/ApiError');

/**
 * Runs after a list of express-validator rules and turns any
 * collected errors into a single 400 response.
 */
module.exports = function validate(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const details = result.array().map((e) => ({
    field: e.path,
    message: e.msg,
  }));

  return next(ApiError.badRequest('Validation failed', details));
};
