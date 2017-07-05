var jwt = require('jsonwebtoken');
var JWTConfig = require('../config/jwt');

// Write a JWT Token and give it to the user as a cookie
var returnToken = function(req, res) {
    if (!req.cookies.jwt) { res.cookie('jwt', jwt.sign({ id: req.user.id}, JWTConfig.jwtSecret)); }
    console.log("Token written to cookie.");
    res.redirect('/profile');
};


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

   // profile is now protected by jwt login
    app.get('/profile', passport.authenticate('jwt-login', {
        failureRedirect: '/login',
        session: false
    }),
    function(req, res) {
        res.render('profile.ejs', {
            user: req.user
        });
    });
    app.get('/logout', function(req, res) {
//        req.logout();
        res.cookie('jwt', '', {expires: new Date(0)});
        res.redirect('/');
    });
    app.post('/signup', passport.authenticate('local-signup', {
//        successRedirect: '/profile',
        failureRedirect: '/signup',
        failureFlash: true,
        session: false
    }), returnToken);
    app.post('/login', passport.authenticate('local-login', {
//        successRedirect: '/profile',
        failureRedirect: '/login',
        failureFlash: true,
        session: false
    }), returnToken);

    app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

    app.get('/auth/facebook/callback',
            passport.authenticate('facebook', {
//                successRedirect : '/profile',
                failureRedirect : '/',
                session: false
            }), returnToken);

    app.get('/auth/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

    app.get('/auth/google/callback',
            passport.authenticate('google', {
//                successRedirect : '/profile',
                failureRedirect : '/',
                session: false
            }), returnToken);

    app.get('/connect/facebook', passport.authenticate('jwt-login', {
        failureRedirect: '/login',
        session: false
    }),
            passport.authenticate('facebook', { scope : 'email' }));

    app.get('/connect/facebook/callback',	
            passport.authenticate('facebook', {
                successRedirect : '/profile',
                failureRedirect : '/',
                session: false
            }));

    app.get('/connect/google', passport.authenticate('jwt-login', {
        failureRedirect: '/login',
            session: false
    }),
            passport.authorize('google', { scope : ['profile', 'email'] }));

    app.get('/connect/google/callback', passport.authenticate('jwt-login', {
        failureRedirect: '/login',
            session: false
    }),
            passport.authorize('google', {
                successRedirect : '/profile',
                failureRedirect : '/',
                session: false
            }));


    function isLoggedIn(req, res, next) {
        if (req.isAuthenticated())
            return next();

        res.redirect('/');
    }
}
