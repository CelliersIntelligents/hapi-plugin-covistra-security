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
var Boom = require('boom'),
    Calibrate = require('calibrate'),
    Joi = require('joi');

module.exports = function(server) {

    var Users = server.plugins['covistra-security'].Users;

    function handler(req, reply) {
        req.log.debug("Verify user %s email", req.params.username);

        Users.model.getByUsername(req.params.username).then(function(user) {
            if(user) {
                if(user.validation_code === req.params.validation_code) {

                    if(user.status === Users.Status.PENDING_EMAIL_VERIFICATION) {

                        return user.confirmEmail({notify: false}).then(function() {
                            if(user.lang === 'fr') {
                                reply.redirect('http://alfredsommelier.com/abonnement/confirmed.html');
                            }
                            else {
                                reply.redirect('http://alfredsommelier.com/signup/confirmed.html');
                            }
                            //return { email_confirmed: true, status: Users.Status.PENDING_FIRST_LOGIN };
                        });
                    }
                    else {
                        throw Boom.badRequest('email has already been validated');
                    }
                }
                else {
                    throw Boom.forbidden('invalid validation_code');
                }

            }
            else {
                throw Boom.notFound('Unknown user:'+req.params.username);
            }

        }).then(Calibrate.response).catch(Calibrate.error).then(reply);

    }

    return {
        method: 'GET',
        path: '/verify/{username}/{validation_code}',
        handler: handler,
        config: {
            tags: ['api', 'security'],
            validate: {
                params: {
                    username: Joi.string().required(),
                    validation_code: Joi.string().required()
                }
            }
        }
    }

};
