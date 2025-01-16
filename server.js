require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const ExcelJS = require("exceljs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setează folderul pentru fișierele statice
app.use(express.static(path.join(__dirname, "public")));

// Middleware pentru autentificare admin
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

// Rute HTML
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/introducere-ruta", (req, res) => res.sendFile(path.join(__dirname, "public", "introducere-ruta.html")));
app.get("/istoric-rute", (req, res) => res.sendFile(path.join(__dirname, "public", "istoric-rute.html")));
app.get("/schimba-parola", (req, res) => res.sendFile(path.join(__dirname, "public", "schimba-parola.html")));
app.get("/mediu-invatare", (req, res) => res.sendFile(path.join(__dirname, "public", "mediu-invatare.html")));
app.get("/plan", (req, res) => res.sendFile(path.join(__dirname, "public", "plan.html")));
app.get("/info", (req, res) => res.sendFile(path.join(__dirname, "public", "info.html")));

app.post("/register", (req, res) => {
    const { name, email, phone, password, role } = req.body;

    // Verifică dacă toate câmpurile sunt completate
    if (!name || !email || !phone || !password) {
        return res.status(400).json({ error: "Toate câmpurile sunt obligatorii." });
    }

    // Hashează parola
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Adaugă utilizatorul în baza de date
    const query = `INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [name, email, phone, hashedPassword, role || "courier"], function (err) {
        if (err) {
            if (err.message.includes("UNIQUE constraint")) {
                return res.status(400).json({ error: "Email-ul este deja utilizat." });
            }
            return res.status(500).json({ error: `Eroare la înregistrare: ${err.message}` });
        }
        res.status(201).json({ message: "Utilizator înregistrat cu succes.", userId: this.lastID });
    });
});

// Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email și parolă necesare" });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: "Credențiale invalide" });
        }
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Credențiale invalide" });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, userId: user.id, role: user.role });
    });
});

// Salvare rută zilnică
app.post("/route", (req, res) => {
    const { userId, name, date, auto, tour, kunde, start, ende } = req.body;
    if (!userId || !name || !date || !auto || !tour || !kunde || !start || !ende) {
        return res.status(400).json({ error: "Toate câmpurile sunt obligatorii" });
    }
    const query = `INSERT INTO routes (userId, name, date, auto, tour, kunde, start, ende) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [userId, name, date, auto, tour, kunde, start, ende], function (err) {
        if (err) {
            return res.status(500).json({ error: "Eroare la salvarea rutei" });
        }
        res.status(201).json({ message: "Rută salvată cu succes" });
    });
});

// Export către Excel
app.get("/admin/export", adminOnly, async (req, res) => {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Routes");
    worksheet.columns = [
        { header: "User ID", key: "userId", width: 15 },
        { header: "Name", key: "name", width: 20 },
        { header: "Date", key: "date", width: 15 },
        { header: "Auto", key: "auto", width: 10 },
        { header: "Tour", key: "tour", width: 10 },
        { header: "Kunde", key: "kunde", width: 10 },
        { header: "Start", key: "start", width: 10 },
        { header: "End", key: "ende", width: 10 },
    ];

    const query = `SELECT * FROM routes`;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: "Eroare la export" });
        }
        rows.forEach((row) => worksheet.addRow(row));
        res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        res.setHeader("Content-Disposition", "attachment; filename=routes.xlsx");
        return workbook.xlsx.write(res).then(() => res.status(200).end());
    });
});

// Pornire server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

