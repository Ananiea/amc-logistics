require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const path = require("path");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";
if (!JWT_SECRET) throw new Error("JWT_SECRET is missing in .env file");

// PostgreSQL Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
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

// Secure login route (using userId instead of email)
app.post("/login", async (req, res) => {
    const { userId, password } = req.body;
    if (!userId || !password) return res.status(400).json({ error: "UserID and password are required" });

    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
        if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
        
        const user = result.rows[0];
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, userId: user.id, role: user.role, name: user.name });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
