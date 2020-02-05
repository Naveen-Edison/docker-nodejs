require('../../config/settings.js');
require('../../config/connection.js');
const cron = require('node-cron');
const jwt = require('jsonwebtoken');

let Notification = require('../../db/models/notification');

const io = require('socket.io')();
io.on('connection', socket => {
  console.log('connected.......!!!');

  let token = socket.handshake.query.token;

  let task;
  jwt.verify(token, process.env.jwt_secret, (err, decoded) => {
    if (err) {
      console.log('token decode error......');
    } else {
      let email = decoded.email;

      task = cron.schedule('*/2 * * * * *', async function() {

        let notifications = await Notification.find({ email: email, read: false, deleted: false });

        let notification_body = {
          length: notifications.length,
          notification_array: notifications,
        };
        socket.emit('notifications', JSON.stringify(notification_body));
      });
    }
  });

  socket.on('disconnect', () => {
    task.stop();
  });

});

io.listen(process.env.socket_port);

cron.schedule('0 */30 * * * *', async function() {
  console.log('restarting........');

  process.exit(0);
});
