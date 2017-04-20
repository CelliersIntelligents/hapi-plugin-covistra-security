/**

 Copyright 2015 Covistra Technologies Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
"use strict";

var P = require('bluebird'),
    _ = require('lodash'),
    Boom = require('boom'),
    fs = require('fs'),
    path = require('path'),
    crypto = require('crypto');

module.exports = function(plugin, log, config) {

    var dbName = config.get('plugins:security:db_ref', 'MAIN');
    var COLNAME = config.get('plugins:security:user_coll', 'users');

    var db = plugin.plugins['covistra-mongodb'][dbName];
    var clock = plugin.plugins['covistra-system'].clock;
    var uniqueCheck = plugin.plugins['covistra-mongodb'].uniqueCheck;
    var TemplateEngine = plugin.plugins['covistra-system'].TemplateEngine;
    var Mailer = plugin.plugins['covistra-mailer'];

    if(Mailer) {

        // Templates will be automatically resolved by the engine
        TemplateEngine.registerTemplate('verify-email', fs.readFileSync(path.resolve(__dirname, "../templates", "verify-email.hbs"), 'utf8'));
        TemplateEngine.registerTemplate('welcome-email', fs.readFileSync(path.resolve(__dirname, "../templates", "welcome-email.hbs"), 'utf8'));
    }
    else {
        log.info("No mailer plugin available. No email will be sent");
    }

    plugin.plugins['covistra-mongodb'].indexManager.registerIndex(dbName, COLNAME, { username: 1});
    plugin.plugins['covistra-mongodb'].indexManager.registerIndex(dbName, COLNAME, { email: 1});

    var STATUS_VALUES = {
        NEW:'NEW',
        PENDING_EMAIL_VERIFICATION:"PENDING_EMAIL_VERIFICATION",
        PENDING_APPROVAL: "PENDING_APPROVAL",
        PENDING_FIRST_LOGIN: "PENDING_FIRST_LOGIN",
        ACTIVE: "ACTIVE",
        SUSPENDED: "SUSPENDED",
        REVOKED: "REVOKED"
    };

    function _encryptPassword(password) {
        var sha1 = crypto.createHash("sha1");
        sha1.update(password);
        return sha1.digest('base64');
    }

    function User(data) {
        _.merge(this, data);

        if(this.email) {
            this.image_url ="//www.gravatar.com/avatar/" + crypto.createHash('md5').update(this.email).digest('hex');
        }
    }

    User.prototype.secure = function() {
        return _.pick(this, "username", "email", "status", "last_presence_ts", "first_name", "last_name", "_id", "groups");
    };

    User.prototype.toJSON = function() {
        return _.omit(this, "password", "validation_code");
    };

    User.prototype.update = function(data) {
        var _this = this;
        var coll = db.collection(COLNAME);
        _.merge(this, data);

        // Handle reset password operations
        if(data.password) {
            data.password = _encryptPassword(this.password);
        }

        return P.promisify(coll.update, coll)({username: this.username}, { $set: data }).then(function() { return _this; });
    };

    User.prototype.delete = function() {
        var coll = db.collection(COLNAME);
        return P.promisify(coll.delete, coll)({username: this.username});
    };

    User.prototype.asReceipt = function() {
        return {
            _id : this._id,
            username: this.username,
            email: this.email,
            status: this.status,
            first_name: this.first_name,
            last_name: this.last_name
        };
    };

    User.prototype.confirmEmail = function(options) {
        var _this = this;
        options = options || {};
        return this.update({status: STATUS_VALUES.PENDING_FIRST_LOGIN}).then(function(result) {
            if(options.notify && Mailer) {
                var appName = config.get('server:info:app_name');

                Mailer.sendRichEmailToUser(config.get('plugins:security:mailer:from', 'no-reply@covistra.com'), _this, {
                    subject: util.format('Welcome to %s!', appName),
                    template: config.get('plugins:security:mailer:templates:welcome', 'welcome-email'),
                    data: _.merge(_this, {
                        appName: appName,
                        base_url: config.get('server:prod:base_url'),
                        copyright: config.get('server:info:copyright')
                    })
                });
            }
            return result;
        });
    };

    function _getByUsername(username) {
        log.debug("Users:getByUsername", username);
        var coll = db.collection(COLNAME);
        var caseInsensitiveUsername = new RegExp('^' + username + '$', 'i');
        return P.promisify(coll.findOne, coll)({$or: [{username: caseInsensitiveUsername}, {email: caseInsensitiveUsername}]}).then(function(data) {
            if(data) {
                log.trace("User %s was found", username);
                return new User(data);
            }
            else {
                log.warn("User %s wasn't found in database", username);
            }
        });
    }

    function _findById(_id) {
        var coll = db.collection(COLNAME);
        return P.promisify(coll.findOne, coll)({_id: _id}).then(function(data) {
            if(data) {
                return new User(data);
            }
        });
    }

    function _create(data) {
        var coll = db.collection(COLNAME);

        var provided_password = data.password;

        if(data.status === STATUS_VALUES.NEW) {

            data.password =_encryptPassword(data.password);
            data.validation_code = crypto.randomBytes(10).toString('hex').toUpperCase();
            data.status = STATUS_VALUES.PENDING_EMAIL_VERIFICATION;
        }

        // Validate username and email uniqueness
        return uniqueCheck(dbName, COLNAME, {username: data.username, email: data.email}).then(function() {
            return P.promisify(coll.insertOne, coll)( _.omit(data, "welcome_email", "provided_password") ).then(function(result) {
                data._id = result.insertedId;

                if(Mailer && data.welcome_email !== "none") {

                    // Create the mail request
                    var mail = {
                        data: _.assign(data, { provided_password: provided_password}),
                        subject: config.get('plugin:security:mailer:registration:subject', 'CMBF: Email confirmation'),
                        template: data.welcome_email || config.get('plugin:security:mailer:templates:verify_email', 'verify-email')
                    };

                    Mailer.sendRichEmailToUser(config.get('plugin:security:mailer:from', 'no-reply@covistra.com'), data, mail);
                }

                return new User(data).asReceipt();
            });
        });

    }

    function _list(filter, options) {
        options = options || {};
        var cursor = db.collection(COLNAME).find(filter);

        if(options.limit) {
            cursor.limit(options.limit);
        }

        if(options.skip) {
            cursor.skip(options.skip);
        }

        if(options.sort) {
            cursor.sort(options.sort);
        }
        return P.promisify(cursor.toArray, cursor)();
    }

    var _authenticate = function (request) {
        log.debug("Users:authenticate", request.username);
        return _getByUsername(request.username).then(function(user) {
            if (user) {
                if (_encryptPassword(request.password) === user.password && _.contains([STATUS_VALUES.ACTIVE,STATUS_VALUES.PENDING_FIRST_LOGIN], user.status) ) {
                    return user.update({last_presence_ts: clock.nowTs(), status: STATUS_VALUES.ACTIVE }).then(function() {
                        log.debug("User %s was successfully authenticated", request.username);
                        return user;
                    });
                }
                else {
                    throw Boom.expectationFailed("User account "+request.username+" is not accessible. Check status");
                }
            }
            else {
                log.warn("Unknown user %s", request.username);
                throw Boom.notFound(request.username);
            }
        });
    };

    var _update = function(data) {
        var coll = db.collection(COLNAME);
        var _id = data._id;
        data = _.omit(data, "_id");
        return P.promisify(coll.updateOne, coll)({username: data.username}, { $set: data }).then(function() { data._id = _id; return data; });
    };

    return {
        model: {
            authenticate: _authenticate,
            getByUsername: _getByUsername,
            create: _create,
            list: _list,
            findById: _findById,
            update: _update
        },
        Status: STATUS_VALUES
    }
};
