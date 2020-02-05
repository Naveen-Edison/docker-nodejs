const apn = require('apn');
var FCM = require('fcm-node');
var path = require('path');

let options = {
  token: {
    key: path.join(__dirname, './ios.p8'),
    keyId: '',
    teamId: '',
  },
  production: false,
};

var serverKey = '';


var mobilePush = {

  ios: async function(deviceToken, title, message) {

    let apnProvider = new apn.Provider(options);

    // Replace deviceToken with your particular token:
    // let deviceToken = "f4745a920df619938891358208e23e353879344018329002faa16976f40cf295";

    // Prepare the notifications
    let notification = new apn.Notification();
    notification.expiry = Math.floor(Date.now() / 1000) + 24 * 3600; // will expire in 24 hours from now
    // notification.badge = 2;
    notification.sound = 'default';
    notification.alert = message;
    notification.payload = { messageFrom: title };

    // Replace this with your app bundle ID:
    notification.topic = 'com.demo.app';

    // Send the actual notification
    await apnProvider.send(notification, deviceToken).then(result => {

      console.log(result);
      // Show the result of the send operation:

      if (result.failed[0]) {
        console.log(result.failed[0].response);

        // return "failed";
      } else {
        console.log(result.sent[0]);

        // return "Success";
      }

    });

    // Close the server
    apnProvider.shutdown();

  },

  android: async function(deviceToken, title, message) {

    var fcm = new FCM(serverKey);

    var sendmessage = { // this may vary according to the message type (single recipient, multicast, topic, et cetera)
      to: deviceToken,
      // collapse_key: 'your_collapse_key',

      notification: {
        title: title,
        body: message,
      },

      // data: { //you can send only notification or only data(or include both)
      //     my_key: 'my value',
      //     my_another_key: 'my another value'
      // }
    };

    fcm.send(sendmessage, function(err, response) {
      if (err) {
        console.log('Something has gone wrong!' + err);
      } else {
        console.log('Successfully sent with response: ', response);
      }
    });

  },

};

module.exports = mobilePush;


