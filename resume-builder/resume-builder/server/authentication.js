'use strict';

const crypto = require('crypto');
const nodemailer = require('nodemailer');
const models = require('models'),
    User = models.user,
    Token = models.token;
const functions = require('functions'),
    uuid = functions.uuidGenerator;
const config = require('config');
const jwt = require('jsonwebtoken');
const passport = require("passport");
const bcrypt = require('bcrypt');

module.exports = {
    login: function (req, res, next) {
        passport.authenticate('local', { session: false }, (err, user, info) => {
            if (err || !user) {
                req.resp = {
                    statusCode: 400,
                    msg: "Something is not right"
                }
                next();
            }
            else {
                req.logIn(user, { session: false }, (err) => {
                    if (err) {
                        req.resp = {
                            status: 400,
                            msg: "Something is not right"
                        }
                        next();
                    } else {
                        const token = jwt.sign({
                            _id: user._id,
                            userName: user.userName,
                            email: user.email,
                        }, 'your_jwt_secret');
                        req.resp = {
                            statusCode: 200,
                            data: {
                                token: token
                            }
                        }
                        next();
                    }
                });
            }
        })(req, res, next);
    },
    signup: function (req, res, next) {
        User.findOne({ email: req.body.email }, function (err, user) {
            if (user) {
                req.resp = {
                    statusCode: 400,
                    msg: 'The email address you have entered is already associated with another account.'
                }
                next();
            };
            const password = bcrypt.hashSync(req.body.password, 10);
            user = new User({
                _id: uuid.v4(),
                userName: req.body.userName,
                fullName: req.body.fullName,
                email: req.body.email,
                isVerified: false,
                mobileNo: 0,
                password: password,
            });

            user.save(function (err) {
                if (err) {
                    req.resp = {
                        statusCode: 500,
                        msg: err.message
                    }
                    next();
                }
                var token = new Token({ _id: user._id, token: crypto.randomBytes(16).toString('hex') });

                token.save(function (err) {
                    if (err) {
                        req.resp = {
                            statusCode: 500,
                            msg: err.message
                        }
                        next();
                    }

                    var transporter = nodemailer.createTransport({
                        service: 'gmail',
                        port: '465',
                        secure: true,
                        auth: {
                            user: config.mailer.user,
                            pass: config.mailer.pass
                        }
                    });
                    var mailOptions = {
                        from: config.mailer.user,
                        to: user.email, subject: 'Account Verification Token',
                        text: 'Hello,\n\n' +
                            'Please verify your account by clicking the link: \n' + config.endpoints.confirm + "?token=" + token.token + '.\n'
                    };
                    transporter.sendMail(mailOptions, function (err) {
                        if (err) {
                            req.resp = {
                                statusCode: 500,
                                msg: err.message
                            }
                            next();
                        }
                        req.resp = {
                            statusCode: 200,
                            msg: 'A verification email has been sent to ' + user.email + '.'
                        }
                        next();
                    });
                });
            });
        });
    },

    confirm: function (req, res, next) {
        Token.findOne({ token: req.query.token }, function (err, token) {
            if (!token) {
                req.resp = {
                    statusCode: 400,
                    msg: 'We were unable to find a valid token. Your token my have expired.'
                }
                next();
            };
            User.findOne({ _id: token._id }, function (err, user) {
                if (!user) {
                    req.resp = {
                        statusCode: 400,
                        msg: 'We were unable to find a user for this token.'
                    }
                    next();
                };
                if (user.isVerified) {
                    req.resp = {
                        statusCode: 400,
                        msg: 'This user has already been verified.'
                    }
                    next();
                };

                user.isVerified = true;
                user.save(function (err) {
                    if (err) {
                        req.resp = {
                            statusCode: 500,
                            msg: err.message
                        }
                        next();
                    }
                    req.resp = {
                        statusCode: 200,
                        msg: "The account has been verified. Please log in."
                    }
                    next();
                });
            });
        });
    }
}