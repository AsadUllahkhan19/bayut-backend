const jwt = require('json-web-token');
require('dotenv').config();

const Users = require('../models/Users')

const checkToken = (req, res, next) => {
    const { authorization } = req.headers;
    if (!authorization.slice(7, authorization.length)) {
        return res.send({ message: 'Token is required.' })
    }
    jwt.decode(process.env.SECRET, authorization.slice(7, authorization.length), async function (err, decodedPayload, decodedHeader) {
        if (err) {
            console.error(err.name, err.message);
            return res.send({ message: err.name });
        }
        else {
            const contextData = await Users.findOne({ email: decodedPayload })
            req.body.context = contextData;
            console.log('tokenDecode', decodedPayload, req.body);
            next();
        }
    })
}

module.exports = checkToken;