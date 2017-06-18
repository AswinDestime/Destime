var LocalStrategy = require('passport-local').Strategy;
var PassportJWT = require('passport-jwt');
var JWTStrategy = PassportJWT.Strategy;
var ExtractJWT = PassportJWT.ExtractJwt;
var JWTcfg = require('./jwt');
var params = {  
    secretOrKey: JWTcfg.jwtSecret,
    jwtFromRequest: ExtractJWT.fromAuthHeader(),
    passReqToCallback: true
};

var Sequelize = require('sequelize');
// substitute as necessary
var sequelize = new Sequelize('DBName', 'user', 'password', {
    host: 'localhost',
    dialect: 'mysql'
});

var User = require('../app/models/user')(sequelize, Sequelize);

module.exports = function(passport) {
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });
    passport.deserializeUser(function(id, done) {
        User.findById(id).then(function(user) {
            if (user) {
                done(null, user.get());
            }
            else {
                done(user.errors, null);
            }
        });
    });
    passport.use('local-signup', new LocalStrategy({
        usernameField: 'name',
        passwordField: 'password',
        passReqToCallback: true
    },
    function(req, name, password, done) {
        process.nextTick(function() {
            User.findOne({where: {name: 'name'}}).then(function(user) {
                //                if (err)
                //                    return done(err);
                if (user) {
                    return done(null, false, req.flash('signupMessage', 'Username taken'));
                } else {
                    var userPassword = User.generateHash(password);
                    var data =
                    {
                        name: name,
                        password: userPassword,
                    };
                    User.create(data).then(function(newUser, created) {
                        if (!newUser) {
                            return done(null, false);
                        }
                        if (newUser) {
                            return done(null, newUser);
                        }
                    });
                }
            });
        });
    }));
    passport.use('local-login', new LocalStrategy({
        usernameField: 'name',
        passwordField: 'password',
        passReqToCallback: true
    },
    function(req, name, password, done) {
        User.findOne({ where: {name: name} }).then(function(user) {
//            if (err) {
//                return done(err);
//            }
            if (!user) {
                return done(null, false, req.flash('loginMessage', 'No user found.'));
            }
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Wrong password.'));
            return done(null, user);
        });
    }));
    passport.use('jwt-login', new JWTStrategy(params, function(req, payload, done) {
        User.findById(payload.id).then(function(user) {
            if (!user) {
                return done(null, false, req.flash('loginMessage', 'No user found.'));
            }
            else {
                return done(null, user);
            }
        });
    }));
};


