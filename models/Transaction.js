const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  fromUpiId: {
    type: String,
    required: true,
  },
  toUpiId: {
    type: String,
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['success', 'failed', 'pending'],
    default: 'pending',
  },
  transactionDate: {
    type: Date,
    default: Date.now,
  },
  transactionId: {
    type: String,
    unique: true,
    required: true,
  },
});

module.exports = mongoose.model('Transaction', transactionSchema); 