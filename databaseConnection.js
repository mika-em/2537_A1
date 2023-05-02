require('dotenv').config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = 'mongodb+srv://mika-em:wabisabi@myfirstcluster.ntwxlxi.mongodb.net/?retryWrites=true&w=majority'
var database = new MongoClient(atlasURI, {useNewUrlParser: true, useUnifiedTopology: true});
module.exports = {database};