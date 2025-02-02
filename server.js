require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect()
    .then(() => console.log("🟢 Connected to PostgreSQL"))
    .catch(err => console.error("🔴 Database connection error:", err));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

function authenticateToken(req, res, next) {
    console.log("📡 Headers primiți:", req.headers);
    
    const token = req.headers.authorization ? req.headers.authorization.split(" ")[1] : null;
    console.log("📡 Token extras de server:", token);

    if (!token) {
        console.log("🔴 Eroare: Niciun token furnizat.");
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("🟢 Token valid. User ID:", decoded.id, "Rol:", decoded.role);
        req.user = decoded;
        next();
    } catch (err) {
        console.log("🔴 Eroare: Token invalid.");
        return res.status(401).json({ error: "Invalid token" });
    }
}

app.get("/dashboard", authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.post("/login", async (req, res) => {
    const { userId, password } = req.body;

    console.log("🔵 Login request received. userId:", userId);
    
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

app.listen(PORT, () => console.log(`🟢 Server running on port ${PORT}`));
