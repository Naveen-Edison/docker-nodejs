const jwt = require('jsonwebtoken');
const Admin = require('../../db/models/admin');


function verifyAdmin(req, res, next) {
  var token = req.headers['x-access-token'] || req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Unauthorized access' });
  }

  jwt.verify(token, process.env.admin_jwt_secret, async(err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, error: 'Unauthorized access' });
    }

    req.email = decoded.email;
    let admin = await Admin.findOne({ email: req.email });
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Unauthorized access' });
    }
    next();

  });
}

module.exports = verifyAdmin;
