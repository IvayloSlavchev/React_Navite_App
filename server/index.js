const express = require('express');
const cors = require('cors');
const users = require('./Users/Users');

const app = express();

app.use(cors());
app.use(express.json());

app.use("/users", users);

app.listen(3001, () => console.log("Server listens on port 3001"))