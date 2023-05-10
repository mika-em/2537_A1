require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const usersModel = require('./models/w1users');

const port = process.env.PORT || 3008;
// this line says that if this var (PORT) is defined, default to using 3000
// this is useful for when we host in hosting sites , which will set the PORT var for us

const app = express();

const Joi = require("joi");

app.use(express.static('public'))


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {
    database
} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set("view engine", "ejs");

//body parser - allows us to use req.body. this is middleware - creates a chain of functions. all the functions that are middleware are executed in order
app.use(express.urlencoded({
    extended: false
}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@myfirstcluster.ntwxlxi.mongodb.net/?retryWrites=true&w=majority`,
    // mongoUrl: mongodb_host,

    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(
    session({
        secret: node_session_secret,
        store: mongoStore, //default is memory store 
        saveUninitialized: false,
        resave: true
    }));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {
            error: "Not Authorized"
        });
        return;
    } else {
        next();
    }
}


app.get("/", (req, res) => {
    res.render("index");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});



app.post("/submitUser", async (req, res) => {
    const {
        name,
        email,
        password,
    } = req.body;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(20).required(),
        password: Joi.string().alphanum().max(20).required(),
    });

    const validationResult = schema.validate({
        name,
        email,
        password
    });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        email: email,
        password: hashedPassword,
        user_type: "user",
        name: name,
    });
    req.session.user = {
        name: name,
        email: email,
        user_type: "user"
    };

    res.redirect('/members');

});

const requireLogin = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        return res.render("not-logged-in");
    }
}


app.get("/login", (req, res) => {
    res.render("logging_in")
});


app.post("/loggingin", async (req, res) => {
    const {
        email,
        password,
        name
    } = req.body;


    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error) {
        return res.status(400).send(`
            <p>That email is invalid</p>
            <a href="/login">Back to Login</a>
        `);
    }

    const result = await userCollection.find({
        email: email
    }).project({
        name: 1,
        email: 1,
        password: 1,
        user_type: 1,
        _id: 1
    }).toArray();

    console.log(result);


    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.user = {
            name: result[0].name
        };
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;
        // console.log(req.session);
        res.render("login", {
            name: result[0].name
        })
        return;
    } else {
        return res.status(400).send(`
            <p>That email/password combination is incorrect</p>
            <a href="/login">Back to Login</a>
        `);
    }

});




app.get('/members', requireLogin, async (req, res) => {
    const name = req.session.user.name;


    console.log(req.session);
    res.render('members', {

        name: name,
    });
});



app.post("/login", (req, res) => {
    const name = req.body.name;
    res.render("login", {
        name: name
    })
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({
        username: 1,
        _id: 1,
        name: 1
    }).toArray();

    res.render("admin", {
        users: result
    });
});


app.post("/promoteToAdmin", async (req, res) => {

    const name = req.body.name;
    console.log(name);
    // console.log(req.body);
    await userCollection.updateOne({
        name: name
    }, {
        $set: {
            user_type: "admin"
        }
    });
    console.log("User promoted");
    res.redirect("/admin");
});

app.post("/demoteToUser", async (req, res) => {
    const name = req.body.name;
    // console.log(req.body);
    console.log(name);
    await userCollection.updateOne({
        name: name
    }, {
        $set: {
            user_type: "user"
        }
    });
    console.log("User demoted");
    res.redirect("/admin");
});


app.use(express.static(__dirname + "/public"));

app.get('*', (req, res) => {
    res.render("404")
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});