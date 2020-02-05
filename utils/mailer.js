var nodemailer = require('nodemailer');


// Mail configuration which is used by node-mailer to send verification and pssword reset mails.

var smtpTransport = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.support_email,
    pass: process.env.support_password,
  },
});

module.exports = smtpTransport;
