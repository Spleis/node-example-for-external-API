const express = require('express');
const jwt = require('jsonwebtoken');
const sha256 = require('crypto-js/sha256');
const bodyParser = require('body-parser')
const crypto = require('crypto');
const app = express();

require('dotenv').config()
const env = process.env;

app.use(bodyParser.json())

const port = 8080;

EXTERNAL_DATA_PUBLIC_KEY_TEST=env.EXTERNAL_DATA_PUBLIC_KEY_TEST;
EXTERNAL_DATA_PUBLIC_KEY_PROD=env.EXTERNAL_DATA_PUBLIC_KEY_PROD;

app.get('*', function (req, res) {
    return res.send('GET request to homepage')
})

function verifyJwtToken(req) {
    const jwtTokenFromRequest = req.headers.authorization;
    return jwt.verify(jwtTokenFromRequest, EXTERNAL_DATA_PUBLIC_KEY_TEST);
}

app.post('*', function (req, res) {
    const { requestId, data } = req.body;

    try {
        const jwtContent = verifyJwtToken(req);
        //Using crypto-js/sha256 library which we use in Spleis
        const hashedBody = sha256(data).toString();
        //Using the built inn crypto library from Node
        const hashedBody2 = crypto
            .createHash('sha256')
            .update(data)
            .digest('hex');

        if (hashedBody !== jwtContent.hashedData || hashedBody2 !== jwtContent.hashedData) {
            throw new Error('The signature in the JWT-Token does not match the hash of the data sent.');
        }

        console.log('Everything is verified and good to go: ', jwtContent);
    } catch (error) {
        console.log('error', error);
        return res.status(401).send({});
    }

    return res.send('GET request')
})

app.listen(port, () => {
    console.log(`Now listening on port ${port}`);
});