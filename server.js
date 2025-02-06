require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";
if (!JWT_SECRET) throw new Error("JWT_SECRET is missing in .env file");

const db = new sqlite3.Database(path.join(__dirname, "amc-logistics.db"), (err) => {
    if (err) console.error("Error connecting to SQLite database:", err.message);
    else console.log("Connected to SQLite database.");
});

// Create tables if not exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'courier'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        name TEXT NOT NULL,
        date TEXT NOT NULL,
        auto TEXT NOT NULL,
        tour INTEGER NOT NULL,
        kunde INTEGER NOT NULL,
        start TEXT NOT NULL,
        ende TEXT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS learning_resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        type TEXT NOT NULL,
        path TEXT NOT NULL
    )`);
});

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests, please try again later."
});
app.use(limiter);

// File upload restrictions
const upload = multer({
    dest: "uploads/",
    limits: { fileSize: 2 * 1024 * 1024 }, // Max 2MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
        if (allowedTypes.includes(file.mimetype)) cb(null, true);
        else cb(new Error("Invalid file type"), false);
    }
});

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Default route
app.get("/", (req, res) => res.redirect("/login"));

// Serve HTML pages
const staticPages = ["login", "dashboard", "admin-create-user", "info", "introducere-ruta", "istoric-rute", "mediu-invatare", "plan", "profile", "schimba-parola"];
staticPages.forEach((page) => {
    app.get(`/${page}`, (req, res) => {
        res.sendFile(path.join(__dirname, "public", `${page}.html`));
    });
});

// Secure login route
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Invalid credentials" });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, userId: user.id, role: user.role });
    });
});

// Secure file upload
app.post("/upload-resource", upload.single("file"), (req, res) => {
    const { title, type } = req.body;
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const filePath = req.file.path;
    db.run("INSERT INTO learning_resources (title, type, path) VALUES (?, ?, ?)", [title, type, filePath], (err) => {
        if (err) return res.status(500).json({ error: "Error saving resource" });
        res.json({ success: true });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
