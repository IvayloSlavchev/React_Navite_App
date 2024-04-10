const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const database = require('../database/databaseConnection');
const dotenv = require('dotenv');

const app = express();
dotenv.config();

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

function validateEmail(email) {
    if (EMAIL_REGEX.test(email) === false) return false;

    return true;
}

function validatePassword(password) {
    if (PASSWORD_REGEX.test(password) === false) return false;

    return true;
}

async function checkIfUserExists(username) {
    const getUser = await database.promise().query('SELECT username FROM users WHERE username=?', [username]);

    return getUser[0].length === 0 ? true : false;
}

function generateToken(payload, expiresIn = '3600s') {
    return jwt.sign(payload, process.env.SECRET_KEY, { expiresIn } )
}

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    const emailValidation = validateEmail(email);
    const passwordValidation = validatePassword(password);
    const checkIsUsernameAvaiavble = await checkIfUserExists(username);

    if(checkIsUsernameAvaiavble === false) return res.status(409).json({ msg: 'User already exists'})

    if(username.length < 3) return res.status(400).json({ msg: "Username should be at least 3 characters" });

    if (emailValidation === false) return res.status(400).json({ msg: "Invalid email" });

    if (passwordValidation === false) return res.status(400).json({
            msg: "Password must be at least 8 characters long, contain at least one lowercase letter, one uppercase letter, one digit, and one special character (@$!%*?&)."
        });

    const hashPassword = await bcrypt.hash(password, 10);

    try {
        await database.promise().query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashPassword, email]);

        return res.status(201).json({ msg: 'User has been created' })
    } catch(error) {
        return res.status(400).json({ msg: "Error has occurred: " + error })
    }

})

app.post('/signin', async(req, res) => {
    const { username, password } = req.body;

    const getUsername = await checkIfUserExists(username);
    const getHashedPasswordFromDatabase = await database.promise().query('SELECT password FROM users WHERE username=?', [username]);

    if(getHashedPasswordFromDatabase[0].length === 0) return res.status(404).json({ msg: "User Not Found" })

    const checkIfPasswordIsCorrect = await bcrypt.compare(password, getHashedPasswordFromDatabase[0][0].password.toString());
    
    if(checkIfPasswordIsCorrect === false) return res.status(401).json({ msg: 'Invalid username or password' });

    const generateJWTToken = generateToken({ username });

    return res.status(200).json({ msg: generateJWTToken })
});

app.get("/user", async(req, res) => {
    const cookie = req.headers["authorization"];
    
    if(cookie === null || cookie === undefined) return res.status(401).json({ msg: 'Unauthorizaed user' });

    const decodeJWT = jwt.decode(cookie.substring(7, ));

    console.log(decodeJWT.username);
    const getUserData = await database.promise().query("SELECT * FROM users WHERE username=?", [decodeJWT.username]);

    return res.status(200).json({msg: getUserData[0] })
})

module.exports = app;