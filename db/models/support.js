const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var supportSchema = mongoose.Schema({
  ticket_id: {
    type: String,
    required: true,
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'user',
  },
  title: {
    type: String,
    required: true,
  },
  type: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  comment: {
    type: Array,
    default: [],
  },
  tx_id: {
    type: String,
    default: '',
  },
  status: {
    type: Number,
    default: 0,
  },
}, { timestamps: true });

var support = mongoose.model('support', supportSchema);

module.exports = support;
