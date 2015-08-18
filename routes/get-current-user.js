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

var Calibrate = require('calibrate');

module.exports = function (server) {

    var Users = server.plugins['covistra-security'].Users.model;

    function handler(req, reply) {
        return Users.getByUsername(req.auth.credentials.bearer.username).then(Calibrate.response).catch(Calibrate.error).then(reply);
    }

    return {
        method: 'GET', path: '/user', handler: handler, config: {
            auth: 'token',
            tags: ['api'],
            description: "Get the full profile of the current user",
            notes: "Current user is determine by the token (bearer)"
        }
    };
};

