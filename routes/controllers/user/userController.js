const express = require('express');
const router = express.Router();
const { Validator } = require('node-input-validator');

// Model

const User = require('../../../db/models/user');
const Locale = require('../../../db/models/locale');
const Activity = require('../../../db/models/activity');
const Notification = require('../../../db/models/notification');

// Middleware

const verifyUser = require('../../middlewares/verifyUser');

module.exports = router;

let getLocale = async function(language, id) {
  try {

    let text = null;
    let locale = await Locale.findOne({ locale_id: id });
    if (!locale) {
      return text;
    }
    if (language === 'en') {
      text = locale.english;
    }
    if (language === 'es') {
      text = locale.spanish;
    }
    return text;

  } catch (err) {

    return null;
  }
};

router.get('/getprofile', verifyUser, async(req, res) => {
  try {

    var user = await User.findOne({ email: req.email });
    if (user) {
      let text = await getLocale(user.language, 'D3dnsBY');
      return res.status(200).json({ success: true, message: !text ? 'Profile Fetched successfully !' : text, data: user });
    } else {
      let language = 'en';
      let text = await getLocale(language, 'uaCABv');
      return res.status(400).json({ success: false, message: !text ? 'User not Found !' : text });
    }

  } catch (err) {

    let language = 'en';
    if (req.body.lang) {
      language = req.body.lang;
    }
    let text = await getLocale(language, 'uaCABv');
    return res.status(400).json({ success: false, message: !text ? 'Please contact the support team.' : text });
  }
});

router.get('/activity', verifyUser, async(req, res) => {
  try {

    var user = await User.findOne({ email: req.email });
    if (user) {
      let activity_log = await Activity.find({user_id: user._id});
      let text = await getLocale(user.language, 'D3dnsBY');
      return res.status(200).json({ success: true, message: !text ? 'Activity Fetched successfully !' : text, data: activity_log });
    } else {
      let language = 'en';
      let text = await getLocale(language, 'uaCABv');
      return res.status(400).json({ success: false, message: !text ? 'User not Found !' : text });
    }

  } catch (err) {
    let language = 'en';
    if (req.body.lang) {
      language = req.body.lang;
    }
    let text = await getLocale(language, 'uaCABv');
    return res.status(400).json({ success: false, message: !text ? 'Please contact the support team.' : text });
  }
});

router.post('/update', verifyUser, async(req, res) => {
  try {

    let validator = new Validator(req.body, {
      user_name: 'required',
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

    let { user_name, lang, mobile } = req.body;

    let language = 'en';

    if (lang) {
      language = lang;
    }

    var user = await User.findOne({ email: req.email });
    if (user) {
      user.user_name = user_name;
      user.language = language;
      user.mobile = mobile;
      await user.save();

      let text = await getLocale(language, 'D3dnsBY');
      return res.status(200).json({ success: true, message: !text ? 'Profile updated successfully !' : text });
    } else {
      let text = await getLocale(language, 'uaCABv');
      return res.status(400).json({ success: false, message: !text ? 'User not Found !' : text });
    }

  } catch (err) {

    let language = 'en';
    if (req.body.lang) {
      language = req.body.lang;
    }
    let text = await getLocale(language, 'uaCABv');
    return res.status(400).json({ success: false, message: !text ? 'Please contact the support team.' : text });
  }
});


router.post('/update/language', verifyUser, async(req, res) => {
  try {


    let validator = new Validator(req.body, {
      lang: 'required',
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

    let { lang } = req.body;

    let language = 'en';

    if (lang) {
      language = lang;
    }

    var user = await User.findOne({ email: req.email });
    if (user) {
      user.language = language;
      await user.save();

      let text = await getLocale(language, 'D3dnsBY');
      return res.status(200).json({ success: true, message: !text ? 'Langauge changed successfully !' : text });
    } else {
      let text = await getLocale(language, 'uaCABv');
      return res.status(400).json({ success: false, message: !text ? 'User not Found !' : text });
    }

  } catch (err) {

    let language = 'en';
    if (req.body.lang) {
      language = req.body.lang;
    }
    let text = await getLocale(language, 'uaCABv');
    return res.status(400).json({ success: false, message: !text ? 'Please contact the support team.' : text });
  }
});


router.get('/notification/getall', verifyUser, async(req, res) => {

  try {

    var user = await User.findOne({ email: req.email });
    if (user) {

      let notification_array = await Notification.find({ user_id: user._id, type: 'PUSH', deleted: false }).sort({ createdAt: -1 });

      return res.status(200).json({ success: true, message: 'Notification Details Fetch Success', data: notification_array });
    }
  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Notification Details Fetch Failed' });
  }
});

router.get('/notification/readall', verifyUser, async(req, res) => {

  try {

    var user = await User.findOne({ email: req.email });
    if (user) {

      let notification_array = await Notification.find({ user_id: user._id, deleted: false, read: false }).sort({ createdAt: -1 });

      for (let data of notification_array) {
        let notification = await Notification.findOne({ _id: data._id });
        notification.read = true;
        await notification.save();
      }

      return res.status(200).json({ success: true, message: 'Notification Details Read Success' });
    }
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Notification Details Read Failed' });
  }
});

router.post('/notification/read', verifyUser, async(req, res) => {

  try {

    let validator = new Validator(req.body, {
      id: 'required',
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
    let id = req.body.id;

    let notification = await Notification.findOne({ _id: id });
    notification.read = true;
    await notification.save();

    return res.status(200).json({ success: true, message: 'Notification Details Read Success' });
  } catch (err) {
    console.log(err);
    return res.status(400).json({ success: false, message: 'Notification Details Read Failed' });
  }
});

router.get('/notification/deleteall', verifyUser, async(req, res) => {

  try {

    var user = await User.findOne({ email: req.email });
    if (user) {

      let notification_array = await Notification.find({ user_id: user._id, deleted: false }).sort({ createdAt: -1 });

      for (let data of notification_array) {
        let notification = await Notification.findOne({ _id: data._id });
        notification.deleted = true;
        await notification.save();
      }

      let doc = await User.findOne({ email: req.email });
      let text = await getLocale(doc.language, 'PvNUUm');
      return res.status(200).json({ success: true, message: !text ? 'Notifications Deleted' : text });
    }
  } catch (err) {
    let doc = await User.findOne({ email: req.email });
    let text = await getLocale(doc.language, 'R6byAj');
    return res.status(400).json({ success: false, message: !text ? "Couldn't delete Notifications" : text });
  }
});

router.post('/notification/delete', verifyUser, async(req, res) => {

  try {

    let validator = new Validator(req.body, {
      id: 'required',
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

    let id = req.body.id;

    let notification = await Notification.findOne({ _id: id });
    notification.deleted = true;
    await notification.save();

    let doc = await User.findOne({ email: req.email });
    let text = await getLocale(doc.language, 'uFLJRT');
    return res.status(200).json({ success: true, message: !text ? 'Notification Deleted' : text });
  } catch (err) {
    let doc = await User.findOne({ email: req.email });
    let text = await getLocale(doc.language, 'O5bH8x');
    return res.status(400).json({ success: false, message: !text ? "Couldn't delete Notification" : text });
  }
});
