'use strict';
const bcrypt 			= require('bcrypt');
const bcrypt_p 			= require('bcrypt-promise');
const jwt           	= require('jsonwebtoken');
const {TE, to}          = require('../services/util.service');
const CONFIG            = require('../config/config');

module.exports = (sequelize, DataTypes) => {
    var Model = sequelize.define('User', {
        firstName : DataTypes.STRING,
        lastName  : DataTypes.STRING,
        email     : {type: DataTypes.STRING, allowNull: false, unique: true, validate: { isEmail: {msg: "Email invalid."} }},
        phone     : {type: DataTypes.STRING, allowNull: true},
        password  : {type: DataTypes.STRING},
        role      : {type: DataTypes.STRING, defaultValue: 2}
    });

    Model.associate = function(models){
        this.Companies = this.belongsToMany(models.Company, {through: 'UserCompany'});
    };

    Model.beforeSave(async (user, options) => {
        if(!user.password)
            user.password = '123456';

        let err;
        if (user.changed('password')){
            let salt, hash
            [err, salt] = await to(bcrypt.genSalt(10));
            if(err) TE(err.message, true);

            [err, hash] = await to(bcrypt.hash(user.password, salt));
            if(err) TE(err.message, true);

            user.password = hash;
        }
    });

    Model.prototype.comparePassword = async function (pw) {
        let err, pass
        if(!this.password) TE('password not set');

        [err, pass] = await to(bcrypt_p.compare(pw, this.password));
        if(err) TE(err);

        if(!pass) TE('invalid password');

        return this;
    }

    Model.prototype.getJWT = function () {
        let expiration_time = parseInt(CONFIG.jwt_expiration);
        return "Bearer "+jwt.sign({user_id:this.id}, CONFIG.jwt_encryption);
    };

    Model.prototype.toWeb = function (pw) {
        let json = this.toJSON();
        return json;
    };

    return Model;
};
