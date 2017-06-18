var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var morgan = require('morgan');
//var mongoose = require('mongoose');
var passport = require('passport');
var flash = require('connect-flash');
var session = require('express-session');

var jwt = require('jsonwebtoken');
//var configDB = require('./config/database');
var User = require('./app/models/user');
var port = process.env.PORT || 8080;
//mongoose.connect(configDB.url);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(morgan('dev'));
app.set('view engine', 'ejs'); // set up ejs for templating

app.use(session({secret: 'catsplosion'  }));
app.use(passport.initialize());
// we will remove session eventually and switch to JWT when the client knows how to send back the token
app.use(passport.session());
app.use(flash());

require('./app/routes')(app, passport);
require('./config/passport')(passport);

app.listen(port);
console.log('Server listening on port ' + port);

