const express = require('express');
const router = express.Router();
const randomstring = require('randomstring');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Validator } = require('node-input-validator');


// Model

const User = require('../../../db/models/user');

// Middleware

const verifyAdmin = require('../../middlewares/verifyAdmin');

// Utils

const sendgrid = require('../../../utils/sendgrid');

module.exports = router;


router.get('/getall', verifyAdmin, async(req, res) => {

  try {

    let doc = await User.find({}).sort({ createdAt: -1 });

    return res.status(200).json({ success: true, message: 'User Details Fetch Success', data: doc, count: doc.length });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'User Details Fetch Failed' });
  }
});


router.post('/create', verifyAdmin, async(req, res) => {
  try {

    let validator = new Validator(req.body, {
      email: 'required',
      password: 'required',
      user_name: 'required',
      lang: 'required',
      mobile: 'required',
    });

    let match = await validator.check();

    if (!match) {
      let errorMessage = [];
      let result = validator.errors;
      Object.keys(result).forEach(key => {
        if (result[key]) {
          errorMessage.push(result[key].message);
        }
      });
      return res.status(400).send({ success: false, inputValid: true, errors: errorMessage});
    }

    let { email, password, user_name, ref_token, lang, mobile } = req.body;

    let language = 'en';

    if (lang) {
      language = lang;
    }

    var emailExist = await User.findOne({ email: email });
    if (emailExist) {
      return res.status(400).json({ success: false, message: 'Email has been registered already' });
    }

    var userExist = await User.findOne({ user_name });
    if (userExist) {
      return res.status(400).json({ success: false, message: 'Username has been registered already' });
    }

    var genSalt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(password, genSalt);

    var referral_token = randomstring.generate(6);

    let referred_by = '';
    if (ref_token) {
      let user = await User.findOne({ referral_token: ref_token });

      if (user) {
        referred_by = user._id;
      }
    }

    let user = new User({
      email,
      password: hash,
      user_name,
      referral_token,
      referred_by,
      mobile,
      language,
    });

    let doc = await user.save();
    if (doc._id) {

      var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '24h' });
      var redirectUrl = process.env.email_verify_url + '/' + token;

      let replacements = {
        username: doc.user_name,
        redirectUrl: redirectUrl,
        emailImages: process.env.email_images,
      };

      let email_array = [];
      email_array.push(email);

      let send = await sendgrid.sendMail(email_array, process.env.verify_email_template, replacements);

      if (send) {
        return res.status(200).json({ success: true, message: 'Registered Successfully. Verification mail has been sent to your email.', data: doc.email });
      } else {
        return res.status(400).json({ success: false, message: 'Did not recieve Verification Email? Click Resend Email' });
      }

    } else {
      return res.status(400).json({ success: false, message: 'Failed to register? Please contact the support team' });
    }
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Please contact the support team.' });
  }

});

router.post('/update', verifyAdmin, async(req, res) => {
  try {

    let validator = new Validator(req.body, {
      id: 'required',
      user_name: 'required',
      lang: 'required',
      mobile: 'required|minLength:6',
    });

    let match = await validator.check();

    if (!match) {
      let errorMessage = [];
      let result = validator.errors;
      Object.keys(result).forEach(key => {
        if (result[key]) {
          errorMessage.push(result[key].message);
        }
      });
      return res.status(400).send({ success: false, inputValid: true, errors: errorMessage});
    }

    let { user_name, lang, mobile, id } = req.body;

    let language = 'en';

    if (lang) {
      language = lang;
    }

    var user = await User.findOne({ _id: id });
    if (user) {
      user.user_name = user_name;
      user.language = language;
      user.mobile = mobile;
      await user.save();

      return res.status(200).json({ success: true, message: 'Profile updated successfully !', data: user });
    } else {
      return res.status(400).json({ success: false, message: 'User not Found !' });
    }

  } catch (err) {
    return res.status(400).json({ success: false, message: 'Please contact the support team.' });
  }
});
