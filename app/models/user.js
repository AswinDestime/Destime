
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
        password: Sequelize.STRING,
        // Facebook info
        facebookId: Sequelize.TEXT,
        facebookToken: Sequelize.TEXT,
        // Google info
        googleId: Sequelize.TEXT,
        googleToken: Sequelize.TEXT
    });
    User.generateHash = function(password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
    }
    User.prototype.validPassword = function(password) {
        return bcrypt.compareSync(password, this.password);
    }
    // running the following command will automatically run the MySQL commands necessary
    // to create a table with the necessary fields to hold our data.
    // it must only be ran once.
    // User.sync({ alter: true });
    return User;

}
