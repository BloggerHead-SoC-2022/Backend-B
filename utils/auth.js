const jwt = require("jsonwebtoken");
require('dotenv').config();

const createJWT = (username, password) => {
    const payload = {
        username,
        password
    };
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
};

module.exports = createJWT;