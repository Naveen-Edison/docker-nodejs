const io = require('socket.io').listen(3001);
// const redis = require('redis');
// const client = redis.createClient();
const jwt = require('jsonwebtoken');

io.on('connection', function(socket) {

    let token = socket.handshake.query.token;

    jwt.verify(token, process.env.jwt_secret, (err, decoded) => {
        if (err) {
            console.log(err);
        } else {
            let email = decoded.email;

            // client.hset(email, 'socketId', socket.id, redis.print);

            // io.to(socket.id).emit("connectionStatus", 'Success');

            // socket.on('disconnect', function() {
            //     client.hdel(email, "socketId", redis.print);
            //     console.log(socket.id, "Removed");
            // })

        }
    });

});

module.exports = io;