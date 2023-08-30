const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    phoneNumber: String,
    password: String,
    accountType: String,
    otpVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now() },
    otpCode: String
})

const Users = mongoose.model('User', UserSchema)

module.exports = Users;

