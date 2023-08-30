const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const bcrypt = require('bcrypt');
const jwt = require('json-web-token');
const yup = require("yup");
require('dotenv').config();

const main = require('./config/db');
const User = require('./models/Users')
const UserMiddleWare = require('./middlewares/UserVerify');
const helpers = require('./helpers/validation')

// Your Twilio Account SID and Auth Token

app.use(cors('*'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

main();

app.use('/', require('./routes/index'));

// Register Method Route
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber, accountType } = req.body;
        const schema = yup.object({
            name: yup.string().required().min(2, 'Minimum length should be 2').max(12, 'Maximum length should be 12'),
            email: yup.string().matches(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, 'Invalid email format').required(),
            password: yup.string().min(5, 'Minimum length should be 5').max(12, 'Minimum length should be 12').required(),
            phoneNumber: yup.string().min(6, 'Invalid phone number').required(),
            accountType: yup.string().required()
        })
        try {
            await schema.validate({ name: req?.body?.name, email: req?.body?.email, password: req?.body?.password, phoneNumber: req?.body?.phoneNumber, accountType: req?.body?.accountType });
        } catch (error) {
            return res.json({ message: error['errors'][0] })
        }
        // if (name == '' || name === null || name === undefined) {
        //     return res.send({ message: 'Name is required.' })
        // }
        // if (email == '' || email === null || email === undefined) {
        //     return res.send({ message: 'Email is required.' })
        // }
        // if (password == '' || password === null || password === undefined) {
        //     return res.send({ message: 'Password is required.' })
        // }
        // if (phoneNumber == '' || phoneNumber === null || phoneNumber === undefined) {
        //     return res.send({ message: 'Number is required.' })
        // }
        // if (accountType == '' || accountType === null || accountType === undefined) {
        //     return res.send({ message: 'Account is required.' })
        // }

        const checkEmail = await User.findOne({ email: email });

        if (checkEmail !== null) {
            return res.send({ message: "Email already exists." })
        }

        // 2. Hash password & Save to mongoose
        const hash = await bcrypt.hash(password, 10)

        // 3. generate OTP
        // Create a Twilio client
        const client = new twilio(process.env.ACCOUNTSID, process.env.AUTHTOKEN);

        const minm = 10000;
        const maxm = 99999;
        const OtpNumber = Math.floor(Math.random() * (maxm - minm + 1)) + minm;

        // 1. Add data to collection
        const saveData = new User({
            name: req?.body?.name,
            email: req?.body?.email,
            password: hash,
            phoneNumber: req?.body?.phoneNumber,
            accountType: req?.body?.accountType,
            otpCode: OtpNumber
        })
        saveData.save();

        // Send an SMS
        client.messages
            .create({
                body: `Mac World Otp Varification Code is ${OtpNumber}.`,
                from: '+17622525559',
                to: '+923149856502'
            })
            .then(message => console.log(`Message SID: ${message.sid}`))
            .catch(error => console.error(`Error: ${error.message}`));
        return res.send({ message: "Success", data: saveData._id })
    } catch (error) {
        console.log("ERORR", error);
    }
})

// Verify Token
app.get('/verify-otp', async (req, res) => {
    try {
        const { otp, userId } = req.query;
        if (otp == '' || otp === null || otp === undefined) {
            return res.send({ message: 'Otp is required.' })
        }
        if (userId == '' || userId === null || userId === undefined) {
            return res.send({ message: 'User Id is required.' })
        }
        const schema = yup.object({
            otp: yup.string().min(5).required().matches(/^[0-9]+$/, "Must be only digits").min(5, 'Must be exactly 5 digits').max(5, 'Must be exactly 5 digits'),
            userId: yup.string().required(),
        })
        try {
            await schema.validate({ otp, userId });
        } catch (error) {
            return res.json({ message: error['errors'][0] });
        }
        const data = await User.findOne({ _id: userId }).select('otpCode');

        if (data?.otpCode === otp) {
            const rs = await User.findOneAndUpdate({ _id: userId }, { otpVerified: true });
            console.log("Update_Response", rs);
            return res.send({ message: 'Success' })
        }
        res.send({ message: 'Invalid Otp' })

    } catch (error) {
        console.log("Error", error);
    }
})

// Login Method Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (email == '' || email === null || email === undefined) {
            return res.send({ message: 'Email is required.' })
        }
        if (password == '' || password === null || password === undefined) {
            return res.send({ message: 'Password is required.' })
        }
        // 1. Authenticate email & password.
        const userData = await User.findOne({ email: email }).select('email password');
        if (email != userData?.email) {
            return res.send({ message: 'Invalid email' });
        }
        const dbPassword = await bcrypt.compare(password, userData?.password);
        if (!dbPassword) {
            return res.send({ message: 'Invalid password' });
        }
        // 2. Generate jwt token.
        // var secret = 'TOPSECRETTTTT';

        // 2.0 encode
        let token1 = '';
        jwt.encode(process.env.SECRET, 'asad@gmail.com', function (err, token) {
            if (err) {
                console.error(err.name, err.message);
            } else {
                token1 = token
                console.log('tokenEncode', token);
            }
        })

        // 3. Return token and user Credentials.
        return res.send({ message: 'Successful', data: { token: token1, userData: userData } })

    } catch (error) {
        console.log("ERORR", error);
    }
})

// Testing API
app.post('/', UserMiddleWare, (req, res) => {
    try {
        const data = helpers({ FirstName: '', lastName: 'Asad' });
        console.log('==========', data)
        return res.send({ message: 'Sucess' })
    } catch (error) {
        console.log('FROM Catch', error)
    }
})

app.listen(4000, () => console.log('Server running 4000'));

// jwt.encode(secret, 'asad@gmail.com', function (err, token) {
        //     if (err) {
        //       console.error(err.name, err.message);
        //     } else {
        //       console.log('tokenEncode', token);

        //       // decode
        //       jwt.decode(secret, token, function (err_, decodedPayload, decodedHeader) {
        //         if (err) {
        //           console.error(err.name, err.message);
        //         } else {
        //           console.log('tokenDecode', decodedPayload, decodedHeader);
        //         }
        //       });
        //     }
        //   });