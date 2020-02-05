const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var adminactivitySchema = mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'user',
  },
  type: {
    type: String,
  },
  text: {
    type: String,
  },
  location: {
    type: String,
  },
  ip: {
    type: String,
  },
}, { timestamps: true });

var adminactivity = mongoose.model('adminactivity', adminactivitySchema);

module.exports = adminactivity;
