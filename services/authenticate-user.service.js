var Joi = require('joi');

module.exports = function(server) {
    "use strict";

    var Users = server.services['covistra-security'].Users;

    /**
     *
     */
    var service = function(msg) {
        return Users.model.authenticate(msg.credentials);
    };

    return {
        pattern:{role:'security', target:'user', action:'authenticate'},
        schema: Joi.object().keys({
            credentials: Joi.object().keys({
                username: Joi.string(),
                password: Joi.string().description('Clear-text password. Will not be stored')
            })
        }),
        callback: service
    }
};
