const mongoose = require('mongoose');
const options = { useNewUrlParser: true, useCreateIndex: true, useUnifiedTopology: true };

// Mongodb connection
mongoose.connect("mongodb://mongo:27017/payment", options);

// Mongodb connection success
mongoose.connection.on('connected', function() {
  console.log('Mongoose connection is open ');
});

// Mongodb connection error
mongoose.connection.on('error', function(err) {
  console.log('Mongoose connection has occured ' + err + ' error');
});

// Mongodb connection disconnected
mongoose.connection.on('disconnected', function() {
  console.log('Mongoose connection is disconnected');
});
