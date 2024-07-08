


const express = require("express");
const bcrypt = require("bcrypt");
const pg = require("pg");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const pool = new pg.Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME
});

pool.connect((err) => {
    if (err) {
        console.error('Connection error', err.stack);
    } else {
        console.log('Connected to the database');
    }
});

app.use(express.json());

// Register
app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log("Register request received for:", username);

        const hashPassword = await bcrypt.hash(password, 8);
        console.log("Password hashed");

        const result = await pool.query(
            "INSERT INTO register (username, password) VALUES ($1, $2) RETURNING * ",
            [username, hashPassword]
        );
        console.log("User registered:", result.rows[0]);

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Error during registration:", error.message);
        res.status(500).send("Server Error");
    }
});

// Login
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log("Login request received for:", username);

        const result = await pool.query("SELECT * FROM register WHERE username = $1", [username]);
        console.log("User query result:", result.rows);

        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        const token = jwt.sign({ userId: user.id }, process.env.SECRET_KEY, {
            expiresIn: "1h"
        });
        console.log("Token generated");

        res.json({ token });
    } catch (error) {
        console.error("Error during login:", error.message);
        res.status(500).send("Server Error");
    }
});

function verifyToken(req, res, next) {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Missing token" });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        console.error("Token verification failed:", error.message);
        res.status(401).json({ message: "Invalid Token" });
    }
}

app.get("/userinfo", verifyToken, (req, res) => {
    res.json({ user: req.user });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});












