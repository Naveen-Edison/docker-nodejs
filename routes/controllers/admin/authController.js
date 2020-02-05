const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
let qrcode = require('qrcode');
let speakeasy = require('speakeasy');
const bcrypt = require('bcryptjs');
const { Validator } = require('node-input-validator');

// Model

const Activity = require('../../../db/models/adminactivity');
const Admin = require('../../../db/models/admin');

// Middleware

const verifyAdmin = require('../../middlewares/verifyAdmin');

module.exports = router;


router.post('/login', async(req, res) => {

  try {

    let validator = new Validator(req.body, {
      email: 'required|email',
      password: 'required',
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

    let { email, password } = req.body;

    let admin = await Admin.findOne({ email: email }).select('+password');

    if (!admin) {
      return res.status(400).json({ success: false, message: 'Incorrect Credentials' });
    }

    let passwordCheck = await bcrypt.compareSync(password, admin.password);
    if (!passwordCheck) {
      return res.status(400).json({ success: false, message: 'Incorrect Credentials' });
    }

    if (admin.tfa_active) {
      return res.status(200).json({ success: true, message: 'Enter your google 2fa', g2fa: true });
    } else {
      let activity = new Activity({
        user_id: admin._id,
        type: 'AUTH',
        text: 'Logged in',
        ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        location: req.ipInfo.city + ', ' + req.ipInfo.country,
      });

      activity.save();
      var token = jwt.sign({ email: process.env.admin_email }, process.env.admin_jwt_secret, { expiresIn: '24h' });
      return res.status(200).json({ success: true, message: 'Login Success', data: token, admin: admin });
    }

  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Login Failed' });
  }
});

router.get('/g2f/get', verifyAdmin, async(req, res) => {
  try {
    var secret = speakeasy.generateSecret({ length: 20 });
    var url = speakeasy.otpauthURL({ secret: secret.ascii, label: 'Admin ' + req.email });
    qrcode.toDataURL(url, async function(err, image_data) {
      if (err) {
        return res.status(400).json({ success: false, message: 'Something went wrong, Try again later !', error: err.message });
      }
      const body = {
        secret: secret.base32,
        img: image_data,
      };

      let user = await Admin.findOne({ email: req.email });
      user.tfa_temp = secret.base32;

      let doc = await user.save();

      if (doc) {
        return res.status(200).json({ success: true, message: 'Google 2FA', data: body });
      }
    });
  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Something went wrong, Try again later !', error: err.message });
  }
});

router.post('/g2f/enable', verifyAdmin, async(req, res) => {
  try {


    let validator = new Validator(req.body, {
      otp: 'required',
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

    let { otp } = req.body;

    let user = await Admin.findOne({ email: req.email });
    var userToken = otp;
    var secret = user.tfa_temp;
    var verified = speakeasy.totp.verify({ secret: secret, encoding: 'base32', token: userToken });

    if (verified === true) {
      user.tfa = user.tfa_temp;
      user.tfa_active = true;
      user.tfa_temp = null;

      await user.save();
      return res.status(200).json({ success: true, message: 'G2F Enabled successfully !' });
    } else {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Please Try again later !' });
  }
});

router.post('/g2f/verify', async(req, res) => {
  try {

    let validator = new Validator(req.body, {
      otp: 'required',
      email: 'required|email',
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

    let { otp, email } = req.body;

    let user = await Admin.findOne({ email: email });

    var secret = user.tfa;
    var verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
    });

    if (verified === true) {
      var token = jwt.sign({ email: user.email }, process.env.admin_jwt_secret, { expiresIn: '24h' });
      return res.status(200).json({ success: true, message: 'loggedin successfully', data: token, user: user });
    } else {
      return res.status(400).json({ success: false, message: 'Otp is incorrect' });
    }
  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Something went wrong' });
  }
});

router.post('/g2f/disable', verifyAdmin, async(req, res) => {
  try {

    let validator = new Validator(req.body, {
      otp: 'required',
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

    let otp = req.body.otp;

    let user = await Admin.findOne({ email: req.email });

    var secret = user.tfa;
    var verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
    });

    if (verified === true) {

      user.tfa = null;
      user.tfa_temp = null;
      user.tfa_active = false;
      let doc = await user.save();
      if (doc) {
        return res.status(200).json({ success: true, message: 'Google Two Factor Disabled Successfully' });
      } else {
        return res.status(400).json({ success: false, message: '2FA disable failed !' });
      }
    } else {
      return res.status(400).json({ success: false, message: 'Invalid OTP !' });
    }

  } catch (err) {
    return res.status(400).json({ success: false, message: 'Something went wrong, Try again later !', error: err.message });
  }
});

router.get('/activity', verifyAdmin, async(req, res) => {

  try {


    let admin = await Admin.findOne({ email: req.email });

    if (!admin){
      return res.status(400).json({ success: false, message: 'Activity Fetch Failed' });
    }

    let doc = await Activity.find({ user_id: admin._id }).sort({ createdAt: -1 });

    return res.status(200).json({ success: true, message: 'Activity Fetch Success', data: doc });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Activity Fetch Failed' });
  }
});
