require('../../config/settings.js');
require('../../config/connection.js');
const Admin = require('../models/admin');
const bcrypt = require('bcryptjs');

var genSalt = bcrypt.genSaltSync(10);
var hash = bcrypt.hashSync(process.env.admin_password, genSalt);

let admin = new Admin({
  email: process.env.admin_email,
  password: hash,
});

admin.save().then(res => {
  console.log(res);
}).catch(err => {
  console.log(err);
});
