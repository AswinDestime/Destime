
//var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');
/*var Schema = mongoose.Schema({
    local: {
        name: String,
        password: String,
        admin: Boolean
    }
});

Schema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

Schema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', Schema);
*/

module.exports = function(sequelize, Sequelize) {
    var User = sequelize.define("User", {
        id: {
            autoIncrement: true,
            primaryKey: true,
            type: Sequelize.INTEGER
        },
        name: Sequelize.TEXT,
        password: Sequelize.STRING
    });
    User.generateHash = function(password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
    }
    User.prototype.validPassword = function(password) {
        return bcrypt.compareSync(password, this.password);
    }

    return User;
}
