const mongoose = require('mongoose');

var userSchema = new mongoose.Schema({
  user_name: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
    select: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },
  tfa_temp: {
    type: String,
  },
  tfa: {
    type: String,
    select: false,
  },
  tfa_active: {
    type: Boolean,
    default: false,
  },
  referral_token: {
    type: String,
  },
  referred_by: {
    type: String,
    ref: 'user',
    default: null,
  },
  referral_amount: {
    type: Number,
    default: 0,
  },
  balance: {
    type: Number,
    default: 0,
  },
  status: {
    type: Boolean,
    default: true,
  },
  dob: {
    type: Date,
  },
  mobile: {
    type: String,
    unique: true,
  },
  pin: {
    type: String,
    default: '',
  },
  pin_status: {
    type: Boolean,
    default: false,
  },
  finger_status: {
    type: Boolean,
    default: false,
  },
  address: {
    type: String,
  },
  zipcode: {
    type: String,
  },
  country: {
    type: String,
  },
  user_type: {
    type: String,
    default: 'NORMAL',
  },
  device_type: {
    type: String,
    default: '',
  },
  device_token: {
    type: String,
    default: '',
  },
  language: {
    type: String,
    default: 'English',
  },
  device_id: {
    type: String,
    default: '',
  },
  active: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

var user = mongoose.model('user', userSchema);

module.exports = user;
