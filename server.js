require("dotenv").config();
const express = require("express");
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
    const token = req.headers.authorization?.split(" ")[1];

    console.log("📡 Token primit de server:", token);

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


// Middleware pentru protecția adminilor
function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Access forbidden: Admins only" });
    }
    next();
}

// Servirea fișierelor HTML protejate
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

protectedPages.forEach((page) => {
    app.get(`/${page}`, authenticateToken, (req, res) => {
        res.sendFile(path.join(__dirname, "public", `${page}.html`));
    });
});

// Servirea fișierului login.html
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Pagina principală (root)
app.get("/", (req, res) => {
    res.redirect("/login");
});

// Login pe bază de ID și parolă (fără criptare)
app.post("/login", async (req, res) => {
    const { userId, password } = req.body;

    console.log("🔵 Login request received. userId:", userId);
    
    if (!userId || !password) {
        console.log("🔴 Eroare: ID sau parola lipsă.");
        return res.status(400).json({ error: "User ID și parola sunt necesare" });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);

        if (result.rows.length === 0) {
            console.log("🔴 Eroare: Utilizatorul NU există în baza de date.");
            return res.status(401).json({ error: "ID invalid sau parola greșită" });
        }

        const user = result.rows[0];
        console.log("🟢 Utilizator găsit:", user);

        console.log("🔍 Parola introdusă:", password);
        console.log("🔍 Parola salvată în BD:", user.password);

        if (password !== user.password) {
            console.log("🔴 Eroare: Parola nu se potrivește!");
            return res.status(401).json({ error: "ID invalid sau parola greșită" });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        console.log("✅ Token JWT generat:", token);

        res.json({ token, userId: user.id, role: user.role, name: user.name });
    } catch (err) {
        console.log("🔴 Eroare la interogarea bazei de date:", err.message);
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
});

// Crearea unui utilizator (doar adminii pot face asta)
app.post("/admin/create-user", authenticateToken, adminOnly, async (req, res) => {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) {
        return res.status(400).json({ error: "Toate câmpurile sunt necesare" });
    }

    try {
        const result = await pool.query(
            "INSERT INTO users (name, email, phone, password, role) VALUES ($1, $2, $3, $4, 'courier') RETURNING id",
            [name, `${phone}@example.com`, phone, password]
        );

        res.json({ message: "Utilizator creat cu succes", userId: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: `Database error: ${err.message}` });
    }
});

// Descărcarea Excel-ului cu turele (doar admin)
app.get("/admin/export", authenticateToken, adminOnly, async (req, res) => {
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
        worksheet.addRows(result.rows);

        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.setHeader("Content-Disposition", "attachment; filename=routes.xlsx");
        return workbook.xlsx.write(res).then(() => res.status(200).end());
    } catch (err) {
        res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
    }
});

pool.query("SELECT NOW()", (err, result) => {
    if (err) {
        console.error("🔴 EROARE: Nu mă pot conecta la PostgreSQL:", err.message);
    } else {
        console.log("🟢 Conexiunea la PostgreSQL este activă. Ora serverului:", result.rows[0].now);
    }
});

// Pornirea serverului
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
