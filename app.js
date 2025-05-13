require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const { ObjectId } = require("mongodb");
const url = require("url");


// Initialize the app
const app = express();

const Joi = require("joi");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const MongoStore = require("connect-mongo");
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

// Start the server
const PORT = process.env.PORT || 8000;

// set the ejs engine
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");

// MongoDB connection
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

//middleware
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: false }));

// Middleware to check authentication
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

app.use("/", (req, res, next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentURL = url.parse(req.url).pathname;
  next();
})

const navLinks = [
  {name: "Home", link: "/"},
  {name: "Dogs", link: "/members"},
  {name: "Login", link: "/login"},
  {name: "Sign Up", link: "/createUser"},
  {name: "Admin", link: "/admin"},
  {name: "404", link: "/404"},
]

// Routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("Thanks for subscribing with your email: " + email);
  }
});

// sign up
app.get("/createUser", (req, res) => {
  res.render("signup", {error: null});
});

// login
app.get("/login", (req, res) => {
  const error = req.query.error;

  res.render("login", { error: error });
});

// logging in
app.post("/loggingin", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const schema = Joi.string().max(50).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    return res.redirect("/login?error=invalid");
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, name: 1, user_type: 1 ,_id: 1 }) // Include 'name' in the projection
    .toArray();

  if (result.length !== 1) {
    console.log("user not found");
    return res.redirect("/login?error=invalid");
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.name = result[0].name; // Use the user's name for the session
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = result[0].user_type; // Use the user's type for the session

    return res.redirect("/loggedIn");
  } else {
    console.log("incorrect password");
    return res.redirect("/login?error=invalid");
  }
});

// logged in page
app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  res.render("loggedin", { name: req.session.name });
});

// submit user
app.post("/submitUser", async (req, res) => {
  const { name, username, password } = req.body;

  // Validate name, username, and password
  const schema = Joi.object({
    name: Joi.string().min(1).required(), // Ensure name is not empty
    username: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, username, password });
  const error = validationResult.error;
  if (error) {
    res.render("signup", { error: error });
    return;
  }

  // Hash the password and insert the user into the database
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    username: username,
    password: hashedPassword,
    user_type: "user",
  });
  console.log("Inserted user");

  // Authenticate the user and redirect to members page
  req.session.authenticated = true;
  req.session.username = username;
  req.session.name = name; // Use the user's name for the session
  req.session.cookie.maxAge = expireTime;
  req.session.user_type = "user";

  res.redirect("/members");
});

// logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("An error occurred while logging out.");
    }
    res.clearCookie("connect.sid"); // Clear the session cookie
    res.redirect("/");
  });
});

function isAdmin(req) {
  if(req.session.user_type === "admin") {
    return true;
  }
  return false;
}

function adminAuthentication(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403)
    const user_type = req.session.user_type;
    res.render("errorMessage", {error: "Not authorized as an admin", user_type: user_type});
    return;
  } else {
    next();
  }
}

// admin page
app.get("/admin", isAuthenticated, adminAuthentication, async (req, res) => {
  const result = await userCollection.find().project({username: 1, _id: 1, name: 1, user_type: 1}).toArray();

  res.render("admin", { name: req.session.name, users: result});
});

app.get("/members", isAuthenticated, (req, res) => {
  const gifs = ["/dog1.gif", "/dog2.gif", "/dog3.gif"];
  // const randomGif = gifs[Math.floor(Math.random() * gifs.length)];

  res.render("members", { gifs: gifs});
});

app.post("/promoteUser", isAuthenticated, adminAuthentication, async (req, res) => {
  const user_id = req.body.user_id;
  await userCollection.updateOne(
      { _id: new ObjectId(user_id) },
      { $set: { user_type: "admin" } }
    );
  res.redirect("/admin");
});

app.post("/demoteUser", isAuthenticated, adminAuthentication, async (req, res) => {
  const user_id = req.body.user_id;
  await userCollection.updateOne({_id: new ObjectId(user_id)},
    {$set: {user_type: "user"}});
  res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
