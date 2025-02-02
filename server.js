require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const ExcelJS = require("exceljs");
const { Pool } = require("pg");
const path = require("path");

// Configurare server
const app = express();
const PORT = process.env.PORT || 3000;

// Conectare la PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necesită pentru conexiuni sigure pe Render
    }
});

pool.connect()
    .then(() => console.log("Connected to PostgreSQL"))
    .catch(err => console.error("Database connection error:", err));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Middleware pentru autentificare
function authenticateToken(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1] || req.query.token;
    if (!token) {
        return res.redirect("/login");
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.redirect("/login");
    }
}

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Lista paginilor protejate
const protectedPages = [
    "dashboard",
    "admin-create-user",
    "info",
    "introducere-ruta",
    "istoric-rute",
    "mediu-invatare",
    "plan",
    "profile",
    "schimba-parola"
];

// Protejăm paginile
protectedPages.forEach((page) => {
    app.get(`/${page}`, authenticateToken, (req, res) => {
        res.sendFile(path.join(__dirname, "public", `${page}.html`));
    });
});

// Pagina principală (root)
app.get("/", (req, res) => {
    res.redirect("/login");
});

// Login pe bază de ID și parolă
app.post("/login", async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ error: "User ID și parola sunt necesare" });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "ID invalid sau parola greșită" });
        }

        const user = result.rows[0];

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "ID invalid sau parola greșită" });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ token, userId: user.id, role: user.role, name: user.name });
    } catch (err) {
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
});

// Pornirea serverului
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
