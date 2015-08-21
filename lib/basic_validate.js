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

module.exports = function(server, log) {

    var Users = server.plugins['covistra-security'].Users;

    return function (username, password, callback) {
        log.trace("Authenticating user Basic:", username);
        return Users.model.authenticate({username: username, password:password}).then(function(user) {
            if(!user) {
                log.error("User %s cannot be authenticated", username);
                return callback(null, false);
            }

            return callback(null, true, user.secure() );
        }).catch(callback);
    };
}