require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const ExcelJS = require("exceljs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// Configurare server
const app = express();
const PORT = process.env.PORT || 3000;

// Configurare baza de date SQLite
const db = new sqlite3.Database("./amc-logistics.db", (err) => {
    if (err) {
        console.error("Error connecting to SQLite database:", err.message);
    } else {
        console.log("Connected to SQLite database.");
    }
});

// Creare tabele dacă nu există
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
        totalTourMontliche INTEGER DEFAULT 0,
        FOREIGN KEY (userId) REFERENCES users (id)
    )`);
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servirea fișierelor HTML
app.use(express.static(path.join(__dirname, "public")));

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Pagina principală (root)
app.get("/", (req, res) => {
    res.redirect("/login");
});

// Middleware pentru autentificare Admin
function adminOnly(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "admin") {
            return res.status(403).json({ error: "Access forbidden: Admins only" });
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
}

// Ruta de login
app.post("/login", (req, res) => {
    console.log("Request Body:", req.body);

    const { userId, password } = req.body;

    if (!userId || !password) {
        console.log("Missing credentials");
        return res.status(400).json({ error: "User ID and password are required" });
    }

    const query = `SELECT * FROM users WHERE id = ?`;
    db.get(query, [userId], (err, user) => {
        console.log("DB Error:", err);
        console.log("User Found:", user);

        if (err || !user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, userId: user.id, role: user.role, name: user.name });
    });
});

// Ruta pentru descărcarea Excel-ului (Admin)
app.get("/admin/export", adminOnly, async (req, res) => {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Routes");

    worksheet.columns = [
        { header: "User ID", key: "userId", width: 10 },
        { header: "Name", key: "name", width: 20 },
        { header: "Date", key: "date", width: 15 },
        { header: "Auto", key: "auto", width: 10 },
        { header: "Tour", key: "tour", width: 10 },
        { header: "Kunde", key: "kunde", width: 10 },
        { header: "Start", key: "start", width: 10 },
        { header: "Ende", key: "ende", width: 10 },
    ];

    db.all("SELECT * FROM routes", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
        }

        rows.forEach((row) => worksheet.addRow(row));
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.setHeader("Content-Disposition", "attachment; filename=routes.xlsx");
        return workbook.xlsx.write(res).then(() => res.status(200).end());
    });
});

// Pornirea serverului
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
