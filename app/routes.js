var jwt = require('jsonwebtoken');
var JWTConfig = require('../config/jwt');

module.exports = function(app, passport) {
    app.get('/', function(req, res) {
        res.render('index.ejs');
    });
    app.get('/login', function(req, res) {
        res.render('login.ejs', { message: req.flash('loginMessage') });
    });
    app.get('/signup', function(req, res) {
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });
   // 
   // app.get('/profile', passport.authenticate('jwt-login', {
   //     session: false,
   //     failureRedirect: '/login',
   //     failureFlash: true
   // }), function(req, res) {
   //     console.log("success");
   //     res.render('profile.ejs', {
   //   //      user: req.user
   //     });
   // });
    app.get('/profile', isLoggedIn, function(req, res) {
        res.render('profile.ejs', {
            user: req.user
        });
    });
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/profile',
        failureRedirect: '/signup',
        failureFlash: true
//        session: false
    }));
    app.post('/login', passport.authenticate('local-login', {
        successRedirect: '/profile',
        failureRedirect: '/login',
        failureFlash: true
//        session: false
    }));
    //, function(req, res, next) {
    //    res.status(200).json(jwt.sign({ id: req.user._id}, JWTConfig.jwtSecret));
    //});


    function isLoggedIn(req, res, next) {
        if (req.isAuthenticated())
            return next();

        res.redirect('/');
    }
}
