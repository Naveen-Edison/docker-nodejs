const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
var randomstring = require('randomstring');
let qrcode = require('qrcode');
let speakeasy = require('speakeasy');
const router = express.Router();
var crypto = require('crypto');
const { Validator } = require('node-input-validator');
// const redis = require('redis');
// var client = redis.createClient();

// Model

const User = require('../../../db/models/user');
const Locale = require('../../../db/models/locale');
const Activity = require('../../../db/models/activity');
const Deviceauth = require('../../../db/models/deviceauth');

// Middleware

const verifyUser = require('../../middlewares/verifyUser');

// Utils

const sendgrid = require('../../../utils/sendgrid');
const socket = require('../../../core/socket/server');

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

router.post('/register', async (req, res) => {
    try {


        let validator = new Validator(req.body, {
            email: 'required|email',
            password: 'required|minLength:6',
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let { email, password, user_name, ref_token, lang, mobile } = req.body;

        let language = 'en';

        if (lang) {
            language = lang;
        }

        var emailExist = await User.findOne({ email: email });
        if (emailExist) {
            let text = await getLocale(language, 'D3dnBY');
            return res.status(400).json({ success: false, message: !text ? 'Email has been registered already' : text });
        }

        var userExist = await User.findOne({ user_name });
        if (userExist) {
            let text = await getLocale(language, 'k1aaKJ');
            return res.status(400).json({ success: false, message: !text ? 'Username has been registered already' : text });
        }

        var mobileExist = await User.findOne({ mobile });
        if (mobileExist) {
            let text = await getLocale(language, 'k1aaKJ');
            return res.status(400).json({ success: false, message: !text ? 'Mobile has been registered already' : text });
        }

        var genSalt = bcrypt.genSaltSync(10);
        var hash = bcrypt.hashSync(password, genSalt);

        var referral_token = randomstring.generate(6);

        let referred_by = '';
        if (ref_token) {
            let user = await User.findOne({ referral_token: ref_token });

            if (user) {
                referred_by = user.email;

            }
        }

        let user = new User({
            email,
            password: hash,
            user_name,
            referral_token,
            referred_by,
            mobile,
            language: language,
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
                let text = await getLocale(language, 'bOKNmy');
                return res.status(200).json({ success: true, message: !text ? 'Registered Successfully. Verification mail has been sent to your email.' : text, data: doc.email });
            } else {
                let text = await getLocale(language, 'pOO60R');
                return res.status(400).json({ success: false, message: !text ? 'Did not recieve Verification Email? Click Resend Email' : text });
            }

        } else {
            let text = await getLocale(language, 'o2UPao');
            return res.status(400).json({ success: false, message: !text ? 'Failed to register? Please contact the support team' : text });
        }
    } catch (err) {

        let language = 'en';
        if (req.body.lang) {
            language = req.body.lang;
        }
        let text = await getLocale(language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team.' : text, error: err.message });
    }
});

router.post('/login', async (req, res) => {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let { email, password, device_id, device_token, device_type, lang } = req.body;

        var user = await User.findOne({ email: email }).select('+password');
        if (!user) {
            let text = await getLocale('en', 'MZdf4D');
            return res.status(400).json({ success: false, message: !text ? 'Kindly Register ' : text });
        }


        let language = user.language;

        if (lang) {
            language = lang;
        }

        if (!user.verified) {
            let text = await getLocale(language, 'NmbN80');
            return res.status(200).json({ success: false, message: !text ? 'Kindly Verify your email' : text, verified: user.verified });
        }

        var hash = user.password;

        let passwordCheck = await bcrypt.compareSync(password, hash);
        if (!passwordCheck) {

            let text = await getLocale(language, 'LF6a1K');
            return res.status(400).json({ success: false, message: !text ? 'Invalid credentials' : text });
        } else {

            if (device_type && device_token && device_id) {
                user.device_type = device_type;
                user.device_token = device_token;
                user.device_id = device_id;
            }
            await user.save();

            if (user.tfa_active) {

                return res.status(200).json({ success: true, message: 'Please verify G2FA', g2fa: true });
            } else {

                let u = req.useragent;

                let device = await Deviceauth.findOne({ email: email, os: (u.isAndroid ? u.platform : u.os), browser: u.browser, version: u.version, deleted: false });
                if (!device) {
                    let deviceauth = new Deviceauth({
                        email: email,
                        os: (u.isAndroid ? u.platform : u.os),
                        browser: u.browser,
                        version: u.version,
                        status: false,
                    });

                    let temp = await deviceauth.save();

                    let redirectUrl = process.env.device_verify_url + '/' + temp._id;

                    let replacements = {
                        username: user.user_name,
                        redirectUrl,
                        emailImages: process.env.email_images,
                        ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                        browser: temp.browser,
                        os: temp.os,
                    };
                    let email_array = [];
                    email_array.push(email);
                    await sendgrid.sendMail(email_array, process.env.authorize_device_template, replacements);
                    return res.status(200).json({ success: true, message: 'Please authorize device from the link sent to your registered email', device: temp._id, verified_device: true });
                } else {

                    if (!device.status) {

                        let redirectUrl = process.env.device_verify_url + '/' + device._id;

                        let replacements = {
                            username: user.user_name,
                            redirectUrl,
                            emailImages: process.env.email_images,
                            ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                            browser: device.browser,
                            os: device.os,
                        };

                        let email_array = [];
                        email_array.push(email);
                        await sendgrid.sendMail(email_array, process.env.authorize_device_template, replacements);
                        return res.status(200).json({ success: true, message: 'Please authorize device from the link sent to your email', device: device._id, verified_device: true });
                    } else {

                        device.verified = true;
                        device.save();

                        let activity = new Activity({
                            user_id: user._id,
                            email: user.email,
                            type: 'AUTH',
                            text: 'Logged in',
                            ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                            location: req.ipInfo.city + ', ' + req.ipInfo.country,
                        });

                        activity.save();
                        var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '24h' });

                        req.session.email = email;
                        req.session.jwt = token;
                        let time = parseInt((process.env.session_expiry), 10);
                        req.session.sessionToken = crypto.randomBytes(16).toString('base64');
                        req.session.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                        req.session.cookie.expires = new Date(Date.now() + time);
                        req.session.cookie.maxAge = time;


                        // client.set(email, token, redis.print);

                        let text = await getLocale(language, '2wlLRc');
                        return res.status(200).json({ success: true, message: !text ? 'Login successful' : text, data: token, g2fa: false, user: user, verified_device: false });
                    }
                }

            }

        }
    } catch (err) {

        let user = await User.findOne({ email: req.body.email });
        let text = await getLocale(user.language, 'uaCABv');

        console.log(err);
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.get('/emailVerify', verifyUser, async (req, res) => {
    try {
        var email = req.email;
        let device = req.useragent;
        var user = await User.findOne({ email: email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Email not found' });
        }

        user.verified = true;
        var doc = await user.save();

        if (doc) {

            let activity = new Activity({
                user_id: user._id,
                email: user.email,
                type: 'AUTH',
                text: 'Email verified',
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                location: req.ipInfo.city + ', ' + req.ipInfo.Wcountry,
            });

            activity.save();

            let os;
            if (device.isAndroid) {
                os = device.platform;
            } else {
                os = device.os;
            }

            let deviceauth = new Deviceauth({
                email: req.email,
                os,
                browser: device.browser,
                version: device.version,
                status: true,
            });

            deviceauth.save();

            let text = await getLocale(user.language, '17m2RJ');
            return res.status(200).json({ success: true, message: !text ? 'Email Verification Successful' : text });

        } else {
            let text = await getLocale(user.language, 'LTCEbM');
            return res.status(400).json({ success: false, message: !text ? 'Email Verification Failed' : text });
        }
    } catch (err) {
        let user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'LTCEbM');
        return res.status(400).json({ success: false, message: !text ? 'Email Verification Failed' : text });

    }
});

router.post('/resendemail', async (req, res) => {

    try {

        let validator = new Validator(req.body, {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        var email = req.body.email;

        var user = await User.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'Kindly Register' });
        }

        if (user.verified) {
            let text = await getLocale(user.language, 'RMz26t');
            return res.status(200).json({ success: false, message: !text ? 'Already Verfied. Kindly Login' : text, verified: user.verified });
        }

        if (!user.status) {
            let text = await getLocale(user.language, 'uaCABv');
            return res.json({ success: false, message: !text ? 'Please contact the support team' : text });
        }

        var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: 300 });
        var redirectUrl = process.env.email_verify_url + '/' + token;

        var replacements = {
            username: user.user_name,
            redirectUrl: redirectUrl,
            emailImages: process.env.email_images,
        };

        let email_array = [];
        email_array.push(email);

        let send = await sendgrid.sendMail(email_array, process.env.verify_email_template, replacements);

        if (send) {

            let activity = new Activity({
                user_id: user._id,
                email: user.email,
                type: 'AUTH',
                text: 'Verification mail resent',
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                location: req.ipInfo.city + ', ' + req.ipInfo.country,
            });

            activity.save();
            let text = await getLocale(user.language, '3FS2PG');
            return res.status(200).json({ success: true, message: !text ? 'Verification link has been sent to your Email' : text });
        } else {
            let text = await getLocale(user.language, 'uaCABv');
            return res.stauts(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
        }

    } catch (err) {
        let user = await User.findOne({ email: req.body.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/forgotpassword', async (req, res) => {
    try {

        let validator = new Validator(req.body, {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        var email = req.body.email;

        var user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Please register' });
        }

        if (!user.verified) {
            return res.status(400).json({ success: false, message: 'Please Verify your email' });
        }

        var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: 900 });
        var redirectUrl = process.env.reset_password_url + '/' + token;

        var replacements = {
            url: process.env.home_url,
            redirectUrl: redirectUrl,
            username: user.user_name,
            emailImages: process.env.email_images,
            ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        };

        let email_array = [];
        email_array.push(email);

        let send = await sendgrid.sendMail(email_array, process.env.forgot_password_template, replacements);

        if (send) {

            let activity = new Activity({
                user_id: user._id,
                email: user.email,
                type: 'AUTH',
                text: 'Forgot password email sent',
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                location: req.ipInfo.city + ', ' + req.ipInfo.country,
            });

            activity.save();
            let text = await getLocale(user.language, 'BHCecw');
            return res.status(200).json({ success: true, message: !text ? 'Link to reset your password has been sent to your Email.' : text });
        } else {
            let text = await getLocale(user.language, 'uaCABv');
            return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
        }

    } catch (err) {
        let user = await User.findOne({ email: req.body.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/resetpassword', verifyUser, async (req, res) => {
    try {

        let validator = new Validator(req.body, {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let email = req.email;
        let { password } = req.body;

        var user = await User.findOne({ email: email }).select('+password');
        if (!user) {
            return res.status(400).json({ success: false, message: 'Kindly Register' });
        }
        var old_password = user.password;

        let passwordCheck = await bcrypt.compareSync(password, old_password);
        if (passwordCheck) {
            let text = await getLocale(user.language, 'VsSIOc');
            return res.status(400).json({ success: false, message: !text ? 'Please enter a diffrent password' : text });
        } else {
            var genSalt = bcrypt.genSaltSync(10);
            var hash = bcrypt.hashSync(password, genSalt);

            user.password = hash;
            await user.save();

            let activity = new Activity({
                user_id: user._id,
                email: user.email,
                type: 'AUTH',
                text: 'Password changed',
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                location: req.ipInfo.city + ', ' + req.ipInfo.country,
            });

            activity.save();
            let text = await getLocale(user.language, 'yhYCuo');
            return res.status(200).json({ success: true, message: !text ? 'Password Change Successful' : text });

        }

    } catch (err) {
        let user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/changepassword', verifyUser, async (req, res) => {

    try {

        let validator = new Validator(req.body, {
            old_password: 'required',
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let email = req.email;

        let { old_password, password } = req.body;


        let doc = await User.findOne({ email: email }).select('+password');

        let passwordCheck = await bcrypt.compareSync(old_password, doc.password);
        if (!passwordCheck) {
            let text = await getLocale(doc.language, 'LdF7h0');
            return res.status(400).json({ success: false, message: !text ? 'Invalid password' : text });
        }

        var genSalt = bcrypt.genSaltSync(10);
        var hash = bcrypt.hashSync(password, genSalt);
        doc.password = hash;

        await doc.save();

        let text = await getLocale(doc.language, 'yhYCuo');
        return res.status(200).json({ success: true, message: !text ? 'Password Change Successful' : text, data: doc });
    } catch (err) {
        var user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.get('/device/checkAuth', async (req, res) => {
    try {

        let { id, email } = req.query;

        let device = await Deviceauth.findOne({ _id: id });

        if (!device) {
            return res.status(400).json({ success: false });
        } else {
            if (device.verified) {
                return res.status(400).json({ success: false });
            }
            if (!device.status) {
                return res.status(200).json({ success: true, verified: false });
            } else {

                let user = await User.findOne({ email: email });
                device.verified = true;
                await device.save();
                var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '24h' });

                let activity = new Activity({
                    user_id: user._id,
                    email: user.email,
                    type: 'AUTH',
                    text: 'Logged in',
                    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                    location: req.ipInfo.city + ', ' + req.ipInfo.country,
                });

                activity.save();

                req.session.email = email;
                req.session.jwt = token;
                let time = parseInt((process.env.session_expiry), 10);
                req.session.sessionToken = crypto.randomBytes(16).toString('base64');
                req.session.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                req.session.cookie.expires = new Date(Date.now() + time);
                req.session.cookie.maxAge = time;

                let text = await getLocale(user.language, '2wlLRc');
                return res.status(200).json({ success: true, message: !text ? 'Login successful' : text, data: token, user: user, verified_device: false, verified: true });
            }
        }

    } catch (err) {
        return res.status(400).json({ success: false, message: 'Please contact the support team' });
    }
});

router.get('/g2f/get', verifyUser, async (req, res) => {
    try {
        var secret = speakeasy.generateSecret({ length: 20 });
        var url = speakeasy.otpauthURL({ secret: secret.ascii, label: req.email });
        qrcode.toDataURL(url, async function(err, image_data) {
            if (err) {
                return res.status(400).json({ success: false, message: 'Please contact the support team', error: err.message });
            }
            const body = {
                secret: secret.base32,
                img: image_data,
            };

            let user = await User.findOne({ email: req.email });
            user.tfa_temp = secret.base32;

            let doc = await user.save();

            if (doc) {
                return res.status(200).json({ success: true, message: 'Google 2FA', data: body });
            }
        });
    } catch (err) {
        return res.status(400).json({ success: false, message: 'Please contact the support team' });
    }
});

router.post('/device/verify', async (req, res) => {

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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let id = req.body.id;

        let doc = await Deviceauth.findOne({ _id: id });

        doc.status = true;

        await doc.save();

        return res.status(200).json({ success: true, message: 'Device Authorization Success', data: doc });
    } catch (err) {
        return res.status(400).json({ success: false, message: 'Device Authorization Failed' });
    }
});

router.post('/g2f/enable', verifyUser, async (req, res) => {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let { otp } = req.body;

        let user = await User.findOne({ email: req.email }).select('+tfa');
        var userToken = otp;
        var secret = user.tfa_temp;
        var verified = speakeasy.totp.verify({ secret: secret, encoding: 'base32', token: userToken });

        if (verified === true) {
            user.tfa = user.tfa_temp;
            user.tfa_active = true;
            user.tfa_temp = null;

            await user.save();

            let activity = new Activity({
                user_id: user._id,
                email: user.email,
                type: 'G2F',
                text: 'Google 2FA Enabled',
                ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                location: req.ipInfo.city + ', ' + req.ipInfo.country,
            });

            activity.save();
            let text = await getLocale(user.language, 'MgndW5');
            return res.status(200).json({ success: true, message: !text ? 'Google 2FA Enabled successfully' : text });
        } else {
            let text = await getLocale(user.language, '5BBdM6');
            return res.status(400).json({ success: false, message: !text ? 'Incorrect Google 2FA Code' : text });
        }

    } catch (err) {
        var user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/g2f/verify', verifyUser, async (req, res) => {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let { otp } = req.body;

        let user = await User.findOne({ email: req.email }).select('+tfa');

        var secret = user.tfa;
        var verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: otp,
        });

        if (verified === true) {
            var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '24h' });
            return res.status(200).json({ success: true, message: 'Success', data: token, user: user });
        } else {
            let text = await getLocale(user.language, '5BBdM6');
            return res.status(400).json({ success: false, message: !text ? 'Incorrect Google 2FA Code' : text });
        }
    } catch (err) {
        var user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/g2f/disable', verifyUser, async (req, res) => {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let otp = req.body.otp;

        let user = await User.findOne({ email: req.email }).select('+tfa');

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

                let activity = new Activity({
                    user_id: user._id,
                    email: user.email,
                    type: 'G2F',
                    text: 'Google 2FA Disabled',
                    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                    location: req.ipInfo.city + ', ' + req.ipInfo.country,
                });

                activity.save();

                let text = await getLocale(user.language, 'WPFt6C');
                return res.status(200).json({ success: true, message: !text ? 'Google 2FA Disabled Successfully' : text });
            } else {
                let text = await getLocale(user.language, 'BN8HJq');
                return res.status(400).json({ success: false, message: !text ? 'Google 2FA disable failed' : text });
            }
        } else {
            let text = await getLocale(user.language, '5BBdM6');
            return res.status(400).json({ success: false, message: !text ? 'Incorrect Google 2FA Code' : text });
        }

    } catch (err) {
        var user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.post('/g2f/auth', async (req, res) => {
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
            return res.status(400).send({ success: false, inputValid: true, errors: errorMessage });
        }

        let { otp, email } = req.body;

        let user = await User.findOne({ email: email }).select('+tfa');

        var secret = user.tfa;
        var verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: otp,
        });

        if (verified === true) {


            let u = req.useragent;

            let device = await Deviceauth.findOne({ email: email, os: (u.isAndroid ? u.platform : u.os), browser: u.browser, version: u.version, deleted: false });
            if (!device) {
                let deviceauth = new Deviceauth({
                    email: email,
                    os: (u.isAndroid ? u.platform : u.os),
                    browser: u.browser,
                    version: u.version,
                    status: false,
                });

                let temp = await deviceauth.save();

                let redirectUrl = process.env.device_verify_url + '/' + temp._id;

                let replacements = {
                    username: user.user_name,
                    redirectUrl,
                    emailImages: process.env.email_images,
                    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                    browser: temp.browser,
                    os: temp.os,
                };
                let email_array = [];
                email_array.push(email);
                await sendgrid.sendMail(email_array, process.env.authorize_device_template, replacements);
                return res.status(200).json({ success: true, message: 'Please authorize device from the link sent to your registered email', device: temp._id, verified_device: true });
            } else {

                if (!device.status) {

                    let redirectUrl = process.env.device_verify_url + '/' + device._id;

                    let replacements = {
                        username: user.user_name,
                        redirectUrl,
                        emailImages: process.env.email_images,
                        ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                        browser: device.browser,
                        os: device.os,
                    };
                    let email_array = [];
                    email_array.push(email);
                    await sendgrid.sendMail(email_array, process.env.authorize_device_template, replacements);
                    return res.status(200).json({ success: true, message: 'Please authorize device from the link sent to your registered email', device: device._id, verified_device: true });
                } else {
                    let activity = new Activity({
                        user_id: user._id,
                        email: user.email,
                        type: 'AUTH',
                        text: 'Logged in',
                        ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
                        location: req.ipInfo.city + ', ' + req.ipInfo.country,
                    });

                    activity.save();
                    var token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '24h' });
                    let text = await getLocale(user.language, '2wlLRc');

                    req.session.email = email;
                    req.session.jwt = token;
                    let time = parseInt((process.env.session_expiry), 10);
                    req.session.sessionToken = crypto.randomBytes(16).toString('base64');
                    req.session.ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                    req.session.cookie.expires = new Date(Date.now() + time);
                    req.session.cookie.maxAge = time;

                    return res.status(200).json({ success: true, message: !text ? 'Login successful' : text, data: token, g2fa: true, user: user, verified_device: false });
                }
            }

        } else {
            let text = await getLocale(user.language, '5BBdM6');
            return res.status(400).json({ success: false, message: !text ? 'Incorrect Google 2FA Code' : text });
        }
    } catch (err) {
        var user = await User.findOne({ email: req.body.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});

router.get('/logout', verifyUser, async (req, res) => {
    try {

        req.session.destroy();

        // client.del(req.email, function(err, response) {
        //     if (response == 1) {
        //         console.log("Deleted Successfully!")
        //     } else {
        //         console.log("Cannot delete")
        //     }
        // });

        return res.status(200).json({ success: true, message: 'Logout successful' });

    } catch (err) {
        console.log(err);
        var user = await User.findOne({ email: req.email });
        let text = await getLocale(user.language, 'uaCABv');
        return res.status(400).json({ success: false, message: !text ? 'Please contact the support team' : text });
    }
});