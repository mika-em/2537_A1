require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const usersModel = require('./models/w1users');

const port = process.env.PORT || 3000;
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


app.get("/", (req, res) => {
    var html = `
    <p>Mika's Demo  ╮(. ❛ ᴗ ❛.) ╭</p>
        <div>
            <a href="/signup">Signup</a>
        </div>
        <div>
            <a href="/login">Login</a>
        </div>
    `;
    res.send(html);
});

app.get("/signup", (req, res) => {
    var html = `
        <p>Signup</p>
        <form action="/submitUser" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name"><br>
            <label for="email">email:</label>
            <input type="text" id="email" name="email"><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br>
            <button type="submit">Submit</button>
        </form>
    `;
    res.send(html);
});

app.post("/submitUser", async (req, res) => {
    const {
        name,
        email,
        password
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
        const missingFields = validationResult.error.details.map(x => x.context.key);
        const message = `Please provide a correct value for: ${missingFields.join(", ")}`;

        return res.status(400).send(`
            <p>${message}</p>
            <a href="/signup">Back to Signup</a>
        `);
    }

    const userExists = await userCollection.findOne({
        email: email
    });

    if (userExists) {
        const message = `User with email ${email} already exists`;

        return res.status(400).send(`
            <p>${message}</p>
            <a href="/signup">Back to Signup</a>
        `);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });

    //print out that user was inserted
    console.log(`User ${name} was inserted  ╮(. ❛ ᴗ ❛.) ╭ `);


    req.session.user = {
        name: name,
        email: email
    };

    res.redirect('/members');
});

app.get("/login", (req, res) => {
    var html = `
        <p>Login</p>
        <form action="/loggingin" method="post">
            <label for="email">Email:</label>
            <input type="text" id="email" name="email"><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br>
            <button type="submit">Submit</button>
        </form>
    `;
    res.send(html);
});

app.post("/loggingin", async (req, res) => {
    const {
        email,
        password
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
        email: 1,
        password: 1,
        name: 1,
        _id: 1
    }).toArray();

    console.log(result);
    if (result.length != 1) {
        return res.status(400).send(`
            <p>That email/password combination is incorrect</p>
            <a href="/login">Back to Login</a>
        `);
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.user = {
            name: result[0].name
        };
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        return res.status(400).send(`
            <p>That email/password combination is incorrect</p>
            <a href="/login">Back to Login</a>
        `);
    }
});



// Middleware function to check if the session exists
const requireLogin = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        return res.send(`Please <a href="/login">log in</a> first ╮(. ❛ ᴗ ❛.) ╭`);
    }
}


// Route for the members page
app.get('/members', requireLogin, async (req, res) => {
    const name = req.session.user.name;

    const randomImageNumber = Math.floor(Math.random() * 3) + 1;
    const imageName = `00${randomImageNumber}.jpg`;

    const html = `
    <p>Hello, ${name}  ╮(. ❛ ᴗ ❛.) ╭ </p>
    <div>
        <img src="${imageName}" style="width:250px;"/>
    </div>
    <div>
        <a href="/logout">Logout</a>
    </div>
    `;
    res.send(html);
});



app.post("/login", (req, res) => {
    const {
        name
    } = req.session;
    const html = `
        <p>Hello, ${name}.</p>
        <div>
            <a href="/members">Go to Members Area</a>
        </div>
        <div>
            <a href="/logout">Logout</a>
        </div>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        } else {
            console.log('Session deleted from database.');
        }
        res.redirect('/');
    });
});


// const protectedRouteForAdminsOnlyMiddlewareFunction = async (req, res, next) => {
//     try {
//         const result = await usersModel.findOne({
//             username: req.session.loggedUsername
//         })
//         if (result?.type != 'administrator') {
//             return res.send('<h1> You are not an admin </h1>')
//         }
//         next();
//     } catch (error) {
//         console.log(error);
//     }
// };
// app.use(protectedRouteForAdminsOnlyMiddlewareFunction);

// app.get('/protectedRouteForAdminsOnly', (req, res) => {
//     res.send('<h1> protectedRouteForAdminsOnly </h1>');
// });

app.get('*', (req, res) => {
    res.status(404).send('<p> 404: Page not found (╯°□°)╯︵ ┻━┻ </p>');
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});