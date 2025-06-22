const mongoose = require('mongoose');

const paymentMethodSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: ['upi', 'card', 'bank_account'],
    required: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  upiId: {
    type: String,
    sparse: true, // Allows null values, but unique for non-null
  },
  cardNumber: {
    type: String,
    sparse: true,
  },
  expiryDate: {
    type: String,
    sparse: true,
  },
  accountNumber: {
    type: String,
    sparse: true,
  },
  ifscCode: {
    type: String,
    sparse: true,
  },
  isDefault: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

const PaymentMethod = mongoose.model('PaymentMethod', paymentMethodSchema);

module.exports = PaymentMethod; 