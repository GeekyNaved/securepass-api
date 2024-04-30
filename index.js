import express, { Router, json } from 'express';
import pkg from 'crypto-js';
import 'dotenv/config';
import cors from 'cors';

const { AES, enc } = pkg;

const app = express();
const router = Router();
app.use('/api', router);

app.use(cors()); // to resolve cors error

app.use(json());

app.listen(3000, () => {
    console.log(`Server Started at ${3000}`)
})

var key = enc.Hex.parse(process.env.KEY);
var iv = enc.Hex.parse(process.env.IV);

// for encryption
router.get('/encrypt', (req, res) => {
    // setting headers to resolve cors error
    res.setHeader("Access-Control-Allow-Origin", "*")
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Max-Age", "1800");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, PATCH, OPTIONS");

    const plainText = req.query.plainText;
    var ciphertext = AES.encrypt(plainText, key, {
        iv: iv
    }).toString();
    if (plainText == undefined || plainText?.length == 0 || plainText?.length < 3) {
        res.status(400).json({
            status: "Bad request",
            msg: "please enter atleast 3 characters",
        });

    } else {
        res.status(200).json({
            status: "accepted",
            msg: "encrypted successfully",
            result: ciphertext,
        });
    }
});
// for decryption
router.get('/decrypt', (req, res) => {
    // setting headers to resolve cors error
    res.setHeader("Access-Control-Allow-Origin", "*")
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Max-Age", "1800");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, PATCH, OPTIONS");

    const encryptedText = req.query.encryptedText;
    var decrypted = AES.decrypt(encryptedText, key, {
        iv: iv
    });

    let decryptedText = enc.Utf8.stringify(decrypted);

    if (decryptedText != undefined && decryptedText?.length != 0) {
        res.status(200).json({
            status: "accepted",
            msg: "decrypted successfully",
            result: decryptedText,
        });

    }
    // if user didn't pass query parameter or pass empty strings in it
    else if (!encryptedText) {
        res.status(400).json({
            status: "Bad request",
            msg: "please enter encryptedText query parameter",
        });
    } else {
        res.status(400).json({
            status: "Bad request",
            msg: "Encrypted text is not valid",
        });
    }
});