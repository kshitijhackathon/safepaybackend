const mongoose = require('mongoose');

const scamReportSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  reportType: {
    type: String,
    enum: ['voice', 'message', 'whatsapp', 'other'],
    required: true,
  },
  scamContact: {
    type: String, // Phone number, email, or social media handle
    trim: true,
    required: function() { return this.reportType !== 'other'; } // Required unless type is 'other'
  },
  scamPlatform: {
    type: String, // e.g., WhatsApp, Telegram, Phone Call, SMS, Email, etc.
    trim: true,
  },
  scamDetails: {
    type: String,
    required: true,
    trim: true,
  },
  screenshotUrl: {
    type: String,
    default: null,
  },
  // You can add more fields like:
  // mediaAttachments: [{ type: String }], // URLs to images/videos of evidence
  // amountLost: { type: Number },
  // dateOfScam: { type: Date },
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'resolved', 'rejected'],
    default: 'pending',
  },
  // Any other relevant fields you want to store
}, { timestamps: true }); // Adds createdAt and updatedAt fields automatically

const ScamReport = mongoose.model('ScamReport', scamReportSchema);

module.exports = ScamReport; 