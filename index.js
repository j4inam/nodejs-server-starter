const express = require("express"),
  path = require("path"),
  logger = require("morgan"),
  cookieParser = require("cookie-parser"),
  mongoose = require("mongoose"),
  bodyParser = require("body-parser");

const app = express();

// Init environment variables
require("dotenv").config();

const env = process.env.NODE_ENV || process.env.DEV_ENV;

// Load server config
const config = require("./config");
const keygen = require("./keygen");

// Configure CORS
let enableCORS = (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Content-Length, X-Requested-With,Access-Control-Allow-Origin"
  );
  next();
};

app.use(enableCORS);

// Set app root
global.appRoot = path.resolve(__dirname);
app.use(logger("dev"));
app.use(bodyParser.json({ limit: "10mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));
app.use(cookieParser());

// Define public directory for serving static resources
app.use(express.static(path.join(__dirname, "public")));

// Generate new encryption key for user auth
keygen.generate().then(() => {
  console.log("New auth keys generated!");
});

//setup mongoose
app.db = mongoose.createConnection(config.mongodb.uri);
app.db.on("error", console.error.bind(console, "mongoose connection error: "));
app.db.once("open", () => {
  //and... we have a data store
  console.log("DB connection successful");
});

// Import mongoose models
require("./models")(app, mongoose);

// Import API Routes
require("./routes")(app);

//setup utilities
app.utility = {};
app.utility.workflow = require("./utils/workflow");

// Fire up the server
app.listen(process.env.PORT || process.env.APP_PORT, () => {
  console.log(
    "Server running at port ",
    process.env.PORT || process.env.APP_PORT
  );
});
