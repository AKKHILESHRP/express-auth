const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
const port = process.env.port;

// creating the database connection
mongoose.connect(process.env.connection)
.then(() => console.log("Database connected successfully."))
.catch((err) => console.log(err));

// creating the schema
const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "name is mandatory"]
    },
    age: {
        type: Number,
        required: [true, "age is mandatory"],
        min: [18, "minimum age is 18"]
    },
    email: {
        type: String,
        required: [true, "email is mandatory"],
    },
    password: {
        type: String,
        required: [true, "password is mandatory"]
    },
    designation: {
        type: String,
        required: [true, "designation is mandatory"]
    },
    salary: {
        type: Number,
        required: [true, "salary is mandatory"]
    }
}, {timestamps: true});

// creating the model
const userModel = mongoose.model(process.env.collectionName, userSchema);

// creating the post request for the data
app.post("/signup", (req, res) => {
    let user = req.body;
    bcrypt.genSalt(10, (err, salt) => {
        if(!err)
        {
            bcrypt.hash(user.password, salt, (err, hpass) => {
                if(!err)
                {
                    user.password = hpass;
                    userModel.create(user)
                    .then((doc) => res.status(201).send({ message: "User Registration successfully." }))
                    .catch((err) => res.status(500).send({ message: "Internal Server error" }))
                }
            })
        }
    })
})

// creating the login request
app.post("/login", (req, res) => {
    let userCred = req.body;
    userModel.findOne({ email: userCred.email })
    .then((user) => {
        if(user !== null)
        {
            bcrypt.compare(userCred.password, user.password, (err, result) => {
                if(result === true)
                {
                    jwt.sign({ email: userCred.email }, process.env.secretKey, (err, token) => {
                        if(!err) res.send({ token: token })
                        else res.status(500).send({ message: "Internal server error" })
                    })
                }
                else res.status(401).send({ message: "Incorrect password" })
            })
        }
        else res.status(404).send({ message: "No user found" })
    })
    .catch((err) => {
        res.send({ message: "Some problem has been occured" })
    })
})

app.get("/securePage", verifyToken, (req, res) => {
    res.send({ message: "Welcome to a secure page" })
})

function verifyToken(req, res, next) {
    let token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, process.env.secretKey, (err, data) => {
        if(!err)
        {
            console.log(data);
            next();
        }
        else res.status(401).send({ message: "Invalid token try again later" })
    })
}


app.listen(port, (err) => {
    if(!err) console.log("Server is up and running");
    else console.log(err);
});