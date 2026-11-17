const express = require('express');
const User = require('../models/User');
const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const { protect, authorize } = require('../middleware/auth');

const router = express.Router();

// Everything below requires a valid access token.
router.use(protect);

// GET /api/users/profile — any logged-in user
router.get(
  '/profile',
  asyncHandler(async (req, res) => {
    res.json({ success: true, data: { user: req.user } });
  })
);

// GET /api/users — admin only
router.get(
  '/',
  authorize('admin'),
  asyncHandler(async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(50, Number(req.query.limit) || 10);

    const [users, total] = await Promise.all([
      User.find().skip((page - 1) * limit).limit(limit).sort('-createdAt'),
      User.countDocuments(),
    ]);

    res.json({
      success: true,
      data: { users, page, limit, total, pages: Math.ceil(total / limit) },
    });
  })
);

// DELETE /api/users/:id — admin only
router.delete(
  '/:id',
  authorize('admin'),
  asyncHandler(async (req, res) => {
    if (req.params.id === req.user._id.toString()) {
      throw ApiError.badRequest('You cannot delete your own account here');
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) throw ApiError.notFound('User not found');

    res.json({ success: true, message: 'User deleted' });
  })
);

module.exports = router;
