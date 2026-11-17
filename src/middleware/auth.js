const User = require('../models/User');
const ApiError = require('../utils/ApiError');
const asyncHandler = require('../utils/asyncHandler');
const { verifyAccessToken } = require('../utils/token');

/**
 * Verifies the Bearer access token and attaches the live user to req.user.
 */
const protect = asyncHandler(async (req, res, next) => {
  const header = req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    throw ApiError.unauthorized('No access token provided');
  }

  const token = header.slice(7).trim();

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw ApiError.unauthorized('Access token expired');
    }
    throw ApiError.unauthorized('Invalid access token');
  }

  const user = await User.findById(payload.sub);
  if (!user) throw ApiError.unauthorized('User no longer exists');

  // A password change or a global logout bumps tokenVersion, which
  // retires every access token minted before it — even unexpired ones.
  if (payload.tv !== user.tokenVersion) {
    throw ApiError.unauthorized('Session is no longer valid. Please log in again');
  }

  req.user = user;
  req.tokenPayload = payload;
  return next();
});

/**
 * Role gate. Use after protect: authorize('admin')
 */
const authorize = (...roles) => (req, res, next) => {
  if (!req.user) return next(ApiError.unauthorized());
  if (!roles.includes(req.user.role)) {
    return next(ApiError.forbidden(`Role '${req.user.role}' cannot access this route`));
  }
  return next();
};

module.exports = { protect, authorize };
