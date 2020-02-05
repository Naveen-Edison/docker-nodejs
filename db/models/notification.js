const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var notificationSchema = mongoose.Schema({

  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'user',
  },
  email: {
    type: String,
  },
  message: {
    type: String,
  },
  read: {
    type: Boolean,
    default: false,
  },
  title: {
    type: String,
  },
  user_type: {
    type: String,
    default: 'USER',
  },
  type: {
    type: String,
    default: 'PUSH',
  },
  user_list: {
    type: [String],
  },
  status: {
    type: Number,
    default: 0,
  },
  deleted: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

var notification = mongoose.model('notification', notificationSchema);

module.exports = notification;
