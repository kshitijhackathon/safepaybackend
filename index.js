const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const User = require('./models/User');
const PaymentMethod = require('./models/PaymentMethod');
const ScamReport = require('./models/ScamReport');
const Transaction = require('./models/Transaction');
const MongoStore = require('connect-mongo');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const multer = require('multer');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const FormData = require('form-data');
require('dotenv').config();

const app = express();

// --- BEGIN CORE MIDDLEWARE CONFIGURATION ---

app.use(cors({
  origin: [
    'https://safepayfrontend-m7ye.vercel.app',
    'http://localhost:5173'
  ],
  credentials: true
}));

app.use(express.json());

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://codefreaks0:nG1CfDIdY5HkorXh@safepay.0ivwjjc.mongodb.net/safepay?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully.'))
.catch(err => console.error('MongoDB connection error:', err));

app.use(session({
  name: 'safepay.sid',
  secret: process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    collectionName: 'sessions',
    ttl: 1000 * 60 * 60 * 24
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    secure: false,
    httpOnly: true,
    sameSite: 'lax',
    path: '/'
  }
}));

app.use((req, res, next) => {
  console.log('Middleware: Session ID on incoming request:', req.sessionID);
  console.log('Middleware: req.session initialized:', !!req.session);
  if (req.session && req.session.userId) {
    console.log('Middleware: req.session.userId:', req.session.userId);
  }
  next();
});

// (All other routes remain unchanged)

const PORT = process.env.PORT || 6900;
app.listen(PORT, () => {
  console.log(`Node.js backend running on port ${PORT}`);
});
