const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var localeSchema = mongoose.Schema({
  locale_id: {
    type: String,
    required: true,
  },
  english: {
    type: String,
    required: true,
  },
  spanish: {
    type: String,
    required: true,
  },
  status: {
    type: Boolean,
    default: true,
  },
}, { timestamps: true });

var locale = mongoose.model('locale', localeSchema);

module.exports = locale;
