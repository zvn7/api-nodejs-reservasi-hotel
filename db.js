const mysql = require("mysql");

const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "hotelresv3"
});

connection.connect((err) => {
    if (err) throw err
    console.log("Connected to database")
})

module.exports = connection