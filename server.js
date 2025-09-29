// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const mongoose = require('mongoose');

const authRoutes = require('./src/routes/auth');

const app = express();

// Middlewares
app.use(helmet());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Routes
app.use('/api/auth', authRoutes);

app.get('/health', (_req, res) => res.json({ ok: true }));

// Only connect DB + listen if not testing
if (process.env.NODE_ENV !== 'test') {
  const PORT = process.env.PORT || 8000;
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/pace';

  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log('Database connected');
      app.listen(PORT, () => console.log(`Server running on :${PORT}`));
    })
    .catch(err => {
      console.error('Mongo connection error:', err);
      process.exit(1);
    });
}

module.exports = app;
