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

var _ = require('lodash');

exports.register = function (server, options, next) {

    server.dependency(['covistra-mongodb'], function(plugin, done) {

        var config = server.plugins['hapi-config'].CurrentConfiguration;
        var log = server.plugins['covistra-system'].systemLog.child({plugin: 'security'});
        var Router = server.plugins['covistra-system'].Router;

        log.debug("Registering the security plugin");

        server.expose('Users', require('./lib/users')(server, log, config));
        server.expose('Applications', require('./lib/applications')(server, log, config));
        server.expose('Tokens', require('./lib/tokens')(server, log, config));

        server.auth.strategy('simple', 'basic', {
            validateFunc: function () {

            }
        });

        // Register our auth strategy
        server.auth.strategy('token', 'bearer-access-token', {
            validateFunc: function () {
            }
        });

        // Set our strategy
        server.auth.strategy('session', 'cookie', _.defaults(config.get('plugins:security:session') || {}, {
            password: 'D@H@H23e@(*#E@HDSADAS@', // cookie secret
            cookie: '_cmbf_auth_session', // Cookie name
            redirectTo: '/login', // Let's handle our own redirections
            isSecure: process.env.NODE_ENV === 'production', // required for non-https applications
            appendNext: true,
            ttl: 30 * 24 * 60 * 60 * 1000 // Set session to 30 days
        }));

        server.select('admin').views({
            engines: {
                html: require('handlebars')
            },
            relativeTo: __dirname,
            path: 'views',
            layout: true,
            partialsPath: 'views/partials',
            layoutPath: "views/layouts"
        });

        // Register routes
        Router.routes(server, __dirname, './routes');

        done();
    });

    next();
};

exports.register.attributes = {
    pkg: require('./package.json')
};


