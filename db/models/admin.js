const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var adminSchema = mongoose.Schema({
  email: {
    type: String,
    default: null,
    unique: true,
  },
  password: {
    type: String,
    default: null,
    select: false,
  },
  tfa_temp: {
    type: String,
  },
  tfa: {
    type: String,
  },
  tfa_active: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

var admin = mongoose.model('admin', adminSchema);

module.exports = admin;
