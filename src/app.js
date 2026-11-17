const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');

const { nodeEnv, clientUrl } = require('./config/env');
const { generalLimiter } = require('./middleware/rateLimiter');
const { notFound, errorHandler } = require('./middleware/errorHandler');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

app.set('trust proxy', 1);

// --- Security and parsing --------------------------------------------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: clientUrl, credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
if (nodeEnv === 'development') app.use(morgan('dev'));
app.use('/api', generalLimiter);

// --- Static test page ------------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Routes ----------------------------------------------------------------
app.get('/api/health', (req, res) =>
  res.json({ success: true, message: 'API is running', env: nodeEnv })
);
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// --- Errors ----------------------------------------------------------------
app.use(notFound);
app.use(errorHandler);

module.exports = app;
