const express = require('express');
const { default: mongoose } = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

//Body parser Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: false }));

mongoose.connect(process.env.DATABASE, {useNewUrlParser:true});
const con = mongoose.connection

con.on('open', () => {
    console.log("Connected to the Database");
});

app.get('/', (req, res) => {
    res.json({"message": "Server is running"});
});

const userRoute = require('./routes/users');
app.use('/users', userRoute);

const blogRoute = require('./routes/blogs');
app.use('/blogs', blogRoute);

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => console.log(`Server is running on the port ${PORT}`));