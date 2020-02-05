const mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var sitesettingsSchema = mongoose.Schema({
  admin_email: {
    type: String,
    default: 'admin@demo.com',
  },
  support_email: {
    type: String,
    default: '',
  },
  fav_icon: {
    type: String,
    default: '',
  },
  site_logo: {
    type: String,
    default: '',
  },
  site_name: {
    type: String,
    default: '',
  },
  site_maintainence: {
    type: Boolean,
    default: false,
  },
  user_share: {
    type: String,
    default: '10',
  },
}, { timestamps: true });

var sitesettings = mongoose.model('sitesettings', sitesettingsSchema);

module.exports = sitesettings;
