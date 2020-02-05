const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const app = express();
const bodyParser = require('body-parser');
const expressip = require('express-ip');
const useragent = require('express-useragent');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

// User
const UserAuthController = require('./controllers/user/authController');
const UserController = require('./controllers/user/userController');

// Admin
const AdminAuthController = require('./controllers/admin/authController');
const LocaleController = require('./controllers/admin/localeController');
const AdminUserController = require('./controllers/admin/userController');
const NotificationController = require('./controllers/admin/notificationController');
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minutes
  max: 500, // limit each IP to 500 requests per windowMs
});

app.use(limiter);

var Ddos = require('ddos');
var ddos = new Ddos({ 
	burst: 10, 
	limit: 24 ,
	testmode : false
})

app.use(ddos.express);


app.use(cors());

app.use(helmet());

app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }));

app.use(useragent.express());

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

app.use(hpp()); 
// To remove data, use:
app.use(mongoSanitize());
// Or, to replace prohibited characters with _, use:
app.use(mongoSanitize({
    replaceWith: '_'
}))

app.use(expressip().getIpInfoMiddleware);


var cookieParser = require('cookie-parser');
var session = require('express-session');

app.set('trust proxy', 1) // trust first proxy

app.use(cookieParser());
app.use(session({
  secret: 'WX3CV5FNuZE1vwCJ2tCIww',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false },
}));

//* ***************** U S E R ***************

// User Auth Api
app.use('/api/auth', UserAuthController);
app.use('/api/user', UserController);


//* ***************** A D M I N ***************

// Admin Auth Api
app.use('/api/adminAuth', AdminAuthController);

// Locale CRUD Api
app.use('/api/admin/locale', LocaleController);

// User CRUD Api
app.use('/api/admin/user', AdminUserController);

// Notification CRUD Api
app.use('/api/admin/notification', NotificationController);


//* ***************** M E R C H E N T ***************


module.exports = app;
