var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var PassportJWT = require('passport-jwt');
var JWTStrategy = PassportJWT.Strategy;
var ExtractJWT = PassportJWT.ExtractJwt;
var JWTcfg = require('./jwt');
var cookieExtractor = function(req) {
    var token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt'];
        console.log(token);
    }
    return token;
};
var params = {  
    secretOrKey: JWTcfg.jwtSecret,
    jwtFromRequest: cookieExtractor,
    passReqToCallback: true
};
var configAuth = require('./auth');
var Sequelize = require('sequelize');
// substitute as necessary
var sequelize = new Sequelize('tableName', 'username', 'password', {
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
        console.log("finding" + payload.id);
        User.findById(payload.id).then(function(user) {
            if (!user) {
                console.log("Nope");
                return done(null, false, req.flash('loginMessage', 'No user found.'));
            }
            else {
                console.log("Yea");
                return done(null, user);
            }
        });
    }));
    passport.use(new FacebookStrategy({
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        passReqToCallback : true,
        profileFields: ['id', 'emails', 'name']
    },
    function(req, token, refreshToken, profile, done) {
        process.nextTick(function() {
            console.log(profile);
            // not logged in, authenticating
            if (!req.user) {
                User.findOne({ where: {facebookId: profile.id} }).then(function(user) {
                    if (user) {
                        return done(null, user); // user found, return that user
                    } else {
                        var data =
                        {
                            facebookId: profile.id,
                            facebookToken: token,
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
            }
            // logged in, authorizing
            else {
                var user = req.user;
                User.findOne({ where: {facebookId: profile.id} }).then(function(facebookUser) {
                    if (facebookUser) {
                        return done(null, false, req.flash("connectMessage", "This Facebook account is already linked to another account."));
                    } else {
                        var data = {
                            facebookId: profile.id,
                            facebookToken: token
                        };
                        User.update(data, {where: {id: user.id} }).then(function(newUser, created) {
                            if (!newUser) {
                                return done(null, false);
                            }
                            if (newUser) {
                                return done(null, newUser);
                            }
                        });
                    }
                });
            }
        });
    }));



};


