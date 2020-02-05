const express = require('express');
const router = express.Router();
var randomstring = require('randomstring');
const Locale = require('../../../db/models/locale');
const verifyAdmin = require('../../middlewares/verifyAdmin');
const { Validator } = require('node-input-validator');

module.exports = router;

router.post('/create', verifyAdmin, async(req, res) => {

  try {

    let validator = new Validator(req.body, {
      english: 'required',
      spanish: 'required',
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

    let { english, spanish } = req.body;

    let locale_id = randomstring.generate(6);

    let locale = new Locale({
      locale_id,
      english,
      spanish,
    });
    await locale.save();

    return res.status(200).json({ success: true, message: 'Locale Success', data: locale });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Locale Failed' });
  }
});

router.get('/getall', verifyAdmin, async(req, res) => {

  try {

    let doc = await Locale.find({status: true}).sort({ createdAt: -1 });

    return res.status(200).json({ success: true, message: 'Locale Details Fetch Success', data: doc });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Locale Details Fetch Failed' });
  }
});

router.post('/update', verifyAdmin, async(req, res) => {

  try {


    let validator = new Validator(req.body, {
      id: 'required',
      english: 'required',
      spanish: 'required',
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
    let { english, spanish } = req.body;

    let doc = await Locale.findOne({ _id: id });
    if (!doc) {
      return res.status(400).json({ success: false, message: 'Locale doesnot exist' });
    }

    doc.english = !english ? doc.english : english;
    doc.spanish = !spanish ? doc.spanish : spanish;

    await doc.save();

    return res.status(200).json({ success: true, message: 'Locale Detail Update Success', data: doc });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Locale Detail Update Failed' });
  }
});

router.post('/delete', verifyAdmin, async(req, res) => {

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

    let doc = await Locale.findOne({ _id: id });
    if (!doc) {
      return res.status(400).json({ success: false, message: 'Locale doesnot exist' });
    }

    doc.status = false;

    await doc.save();

    return res.status(200).json({ success: true, message: 'Locale Delete Success', data: doc });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Locale Delete Failed' });
  }
});
