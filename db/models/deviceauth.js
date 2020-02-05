const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var deviceauthSchema = mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  os: {
    type: String,
    required: true,
  },
  browser: {
    type: String,
    required: true,
  },
  version: {
    type: String,
    required: true,
  },
  status: {
    type: Boolean,
    default: false,
  },
  deleted: {
    type: Boolean,
    default: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

var deviceauth = mongoose.model('deviceauth', deviceauthSchema);

module.exports = deviceauth;
