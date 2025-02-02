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

// Servirea fișierelor HTML
app.use(express.static(path.join(__dirname, "public")));

const staticPages = [
    "login",
    "dashboard",
    "admin-create-user",
    "info",
    "introducere-ruta",
    "istoric-rute",
    "mediu-invatare",
    "plan",
    "profile",
    "schimba-parola",
];

staticPages.forEach((page) => {
    app.get(`/${page}`, (req, res) => {
        res.sendFile(path.join(__dirname, "public", `${page}.html`));
    });
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
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const user = result.rows[0];

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ token, userId: user.id, role: user.role, name: user.name });
    } catch (err) {
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
});

// Ruta de înregistrare utilizator
app.post("/register", async (req, res) => {
    const { name, email, phone, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO users (name, email, phone, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [name, email, phone, hashedPassword, role || "courier"]
        );
        res.status(201).json({ message: "User created", user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
});

// Ruta pentru înregistrarea unei ture
app.post("/routes", async (req, res) => {
    const { userId, name, date, auto, tour, kunde, start, ende } = req.body;

    try {
        const result = await pool.query(
            "INSERT INTO routes (userId, name, date, auto, tour, kunde, start, ende) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
            [userId, name, date, auto, tour, kunde, start, ende]
        );
        res.status(201).json({ message: "Route added", route: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
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

    try {
        const result = await pool.query("SELECT * FROM routes");

        result.rows.forEach((row) => worksheet.addRow(row));
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.setHeader("Content-Disposition", "attachment; filename=routes.xlsx");
        return workbook.xlsx.write(res).then(() => res.status(200).end());
    } catch (err) {
        res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
    }
});

// Pornirea serverului
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
