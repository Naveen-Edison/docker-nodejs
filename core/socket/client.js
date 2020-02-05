var io = require('socket.io-client');

var socket = io.connect('http://localhost:3001/', {
	query:{
		token : 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImVkaUBuZXh0YXp5LmNvbSIsImlhdCI6MTU4MDIwMTI1NSwiZXhwIjoxNTgwMjg3NjU1fQ.bo2a01foGU69uMikVHmbuyORNqjyLFBcmz6WKTAINcA'
	},
    reconnection: true,
});

socket.on('connect', function() {

    console.log('connected to Bot Server web socket');
    socket.on('connectionStatus', data => {
        console.log(data);
    });

    socket.on('pushNotification', data => {
        console.log(data);
    });

});