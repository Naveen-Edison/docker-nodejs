const jwt = require('jsonwebtoken');
const User = require('../../db/models/user');
// const redis = require('redis');
// var client = redis.createClient();

async function verifyUser(req, res, next) {

    var session_jwt = req.session.jwt;
    var sessionToken = req.session.sessionToken;
    var sessionIp = req.session.ip;
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    var token = req.headers['x-access-token'] || req.headers['authorization'];

    if (!token || session_jwt !== token || !sessionToken || ip !== sessionIp) {
        return res.status(401).json({ success: false, message: 'Unauthorized access' });
    }

    jwt.verify(token, process.env.jwt_secret, async (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Unauthorized access' });
        }
        req.email = decoded.email;

        // client.get(decoded.email, function(error, result) {
        //     if (error) {
        //         return res.status(401).json({ success: false, message: 'Unauthorized access' });
        //     }
        //     console.log('GET result ->', result)
        // });

        let user = await User.findOne({ email: req.email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Unauthorized access' });
        }
        if (!user.status) {
            return res.status(401).json({ success: false, message: 'Unauthorized access' });
        }
        next();
    });
}

module.exports = verifyUser;