require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const ObjectId = require('mongodb').ObjectId;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const { UnorderedBulkOperation } = require("mongodb");

const expireTime = 24 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

app.use("/public", express.static("./public"));

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}.i0p5mcg.mongodb.net/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render("index", {user: {name: req.session.name}});
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    var failResponce = "invalidSignup";

    const nameSchema = Joi.string().alphanum().required();
    const emailSchema = Joi.string().email().required();
    const passSchema = Joi.string().required();

    if((nameSchema.validate(name)).error != null)
    {
        res.render("invalidSignup", {error: {type: "Name"}});
        return;
    }
    else if (emailSchema.validate(email).error != null) {
        res.render(failResponce, { error: { type: "Email" } });
        return;
    }
    else if (passSchema.validate(password).error != null) {
        res.render(failResponce, { error: { type: "Password" } });
        return;
    }
    else
    {
        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ email: email, name: name, user_type: "user", password: hashedPassword });

        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;
        res.redirect("/members");
        return;
    }
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    var failResponce = `invalidLogin`;

    const emailSchema = Joi.string().email().required();
    const passSchema = Joi.string().required();

    var validationResult = emailSchema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render(failResponce);
        return;
    }

    var validationResult = passSchema.validate(password);
    if(validationResult.error != null)
    {
        res.render(failResponce);
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, password: 1, _id: 1, user_type: 1 }).toArray();

    if (result.length != 1) {
        res.render(failResponce);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        req.session.admin = (result[0].user_type === 'admin');

        res.redirect('/members');
        return;
    }
    else {
        res.render(failResponce);
        return;
    }
});

app.get('/members', (req, res) => {

    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    res.render("members", { user: { name: req.session.name } });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    else if (!req.session.admin)
    {
        res.render("denied");
        return;
    }

    loadAdminPage(res);
});

async function loadAdminPage(res)
{
    const result = await userCollection.find({}).toArray();
    console.log("Returning result;");
    res.render("admin", {users: result});
}

app.get('/statusPromote/:user', (req, res) => {
    if (!req.session.authenticated
        || !req.session.admin) {
        res.redirect('/');
        return;
    }

    var user = req.params.user;
    promoteUser(user, res);
});

async function promoteUser(user, res)
{
    var id = user;
    await userCollection.updateOne(
        { _id:new ObjectId(user) }, // Filter
        { $set: { user_type: "admin" } } // Update

    );
    res.redirect("/admin");
}

app.get('/statusDemote/:user', (req, res) => {
    if (!req.session.authenticated
        || !req.session.admin) {
        res.redirect('/');
        return;
    }

    var user = req.params.user;
    demoteUser(user, res);
});

async function demoteUser(user, res) {
    var id = user;
    await userCollection.updateOne(
        { _id: new ObjectId(user) }, // Filter
        { $set: { user_type: "user" } } // Update
    );

    res.redirect("/admin");
}

function testFunction()
{
    console.log("Wow");
}

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 