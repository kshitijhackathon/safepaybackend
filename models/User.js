const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  phone: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    unique: true,
    sparse: true
  },
  address: {
    type: String,
    trim: true,
  },
  dob: {
    type: Date,
  },
  paymentMethods: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PaymentMethod',
  }],
  scamReports: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScamReport',
  }],
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User; 