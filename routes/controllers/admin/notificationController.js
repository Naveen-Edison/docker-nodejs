const express = require('express');
const router = express.Router();
const { Validator } = require('node-input-validator');
// const redis = require('redis');
// var client = redis.createClient();

// Model

const Admin = require('../../../db/models/admin');
const User = require('../../../db/models/user');
const Notification = require('../../../db/models/notification');

// Middleware

const verifyAdmin = require('../../middlewares/verifyAdmin');

// Utils

const sendgrid = require('../../../utils/sendgrid');
const pushNotification = require('../../../core/push/push');
const socket = require('../../../core/socket/server');


module.exports = router;


router.post('/send', verifyAdmin, async (req, res) => {

    try {

        let validator = new Validator(req.body, {
            title: 'required',
            message: 'required',
            type: 'required',
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

        let { title, message, user_type, type, user_list } = req.body;

        let admin = await Admin.findOne({ email: req.email });
        if (admin) {
            let notification = new Notification({
                user_id: admin._id,
                email: admin.email,
                message,
                title,
                user_type,
                type,
                user_list,
            });
            await notification.save();
        }

        if (type === 'PUSH') {
            if (user_type !== 'ALL' && user_list.length > 0) {
                for (let data of user_list) {
                    let user = await User.findOne({ _id: data });
                    let notification = new Notification({
                        user_id: user._id,
                        email: user.email,
                        message,
                        title,
                        user_type,
                        type,
                    });

                    await notification.save();

                    let push_data = {
                        title,
                        message
                    }

                    // await client.hgetall(user.email, function(err, result) {
                    //     if (result) {
                    //         socket.to(result.socketId).emit("pushNotification", push_data);
                    //     }
                    // });

                    if (user.device_type === 'ios') {
                        await pushNotification.ios(user.device_token, title, message);
                    }
                    if (user.device_type === 'android') {
                        await pushNotification.android(user.device_token, title, message);
                    }

                }
            } else {
                let List_User = await User.find();
                for (let user of List_User) {
                    let notification = new Notification({
                        user_id: user._id,
                        email: user.email,
                        message,
                        title,
                        user_type,
                        type,
                    });
                    await notification.save();

                    let push_data = {
                        title,
                        message
                    }

                    // await client.hgetall(user.email, function(err, result) {
                    //     if (result) {
                    //         socket.to(result.socketId).emit("pushNotification", push_data);
                    //     }
                    // });

                    if (user.device_type === 'ios') {
                        await pushNotification.ios(user.device_token, title, message);
                    }
                    if (user.device_type === 'android') {
                        await pushNotification.android(user.device_token, title, message);
                    }

                }
            }

        }

        if (type === 'MAIL') {
            if (user_type !== 'ALL' && user_list.length > 0) {

                let email_array = [];
                for (let data of user_list) {
                    let user = await User.findOne({ _id: data });
                    let notification = new Notification({
                        user_id: user._id,
                        email: user.email,
                        message,
                        title,
                        user_type,
                        type,
                    });

                    await notification.save();


                    email_array.push(user.email);
                }

                let replacements = {
                    title: title,
                    message: message,
                    emailImages: process.env.email_images,
                };

                let send = await sendgrid.sendMail(email_array, process.env.custom_mail_template, replacements);

                if (send) {
                    return res.status(200).json({ success: true, message: 'Email Notification Send successfully.' });
                } else {
                    return res.status(400).json({ success: false, message: 'Email Notification Send Failed.' });
                }
            } else {
                let List_User = await User.find();

                let email_array = [];
                for (let user of List_User) {
                    let notification = new Notification({
                        user_id: user._id,
                        email: user.email,
                        message,
                        title,
                        user_type,
                        type,
                    });
                    await notification.save();

                    email_array.push(user.email);
                }

                let replacements = {
                    title: title,
                    message: message,
                    emailImages: process.env.email_images,
                };

                let send = await sendgrid.sendMail(email_array, process.env.custom_mail_template, replacements);

                if (send) {
                    return res.status(200).json({ success: true, message: 'Email Notification Send successfully.' });
                } else {
                    return res.status(400).json({ success: false, message: 'Email Notification Send Failed.' });
                }
            }
        }


        return res.status(200).json({ success: true, message: 'Notification send successfully !' });
    } catch (err) {
        console.log(err);
        return res.status(400).json({ success: false, message: 'Failed to send Notification !' });
    }
});

router.get('/list', verifyAdmin, async (req, res) => {

    try {

        let admin = await Admin.findOne({ email: req.email });
        if (admin) {
            let notification = await Notification.find({ user_id: admin._id });
            return res.status(200).json({ success: true, message: 'Notification Fetched successfully !', data: notification });
        } else {
            return res.status(400).json({ success: false, message: 'Failed to fetch Notification !' });
        }

    } catch (err) {
        console.log(err);
        return res.status(400).json({ success: false, message: 'Failed to send Notification !' });
    }
});