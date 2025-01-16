require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const ExcelJS = require("exceljs");

const app = express();
const PORT = process.env.PORT || 3000;

function adminOnly(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1]; // Extrage token-ul din header
    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Decodează token-ul
        if (decoded.role !== "admin") { // Verifică rolul utilizatorului
            return res.status(403).json({ error: "Access forbidden: Admins only" });
        }
        next(); // Continuă la următorul middleware sau logică
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route: Test Server
app.get("/", (req, res) => {
    res.status(200).send("AMC Logistics API is running with SQLite!");
});

// Route: Register
app.post("/register", (req, res) => {
    const { name, email, phone, password, role } = req.body;

    if (!name || !email || !phone || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = `INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [name, email, phone, hashedPassword, role || "courier"], function (err) {
        if (err) {
            if (err.message.includes("UNIQUE constraint")) {
                return res.status(400).json({ error: "Email already in use" });
            }
            return res.status(500).json({ error: `Registration failed: ${err.message}` });
        }
        res.status(201).json({ message: "User registered successfully", userId: this.lastID });
    });
});

// Route: Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role }, // Include rolul utilizatorului în token
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );
    });
});

// Route: Save Route
app.post("/route", (req, res) => {
    const { userId, name, date, auto, tour, kunde, start, ende } = req.body;

    if (!userId || !name || !date || !auto || !tour || !kunde || !start || !ende) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const queryTotal = `SELECT COUNT(*) AS total FROM routes WHERE userId = ? AND date >= date('now', 'start of month')`;
    db.get(queryTotal, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ error: `Failed to calculate total: ${err.message}` });
        }

        const totalTourMontliche = result.total + 1;

        const query = `INSERT INTO routes (userId, name, date, auto, tour, kunde, start, ende, totalTourMontliche) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        db.run(query, [userId, name, date, auto, tour, kunde, start, ende, totalTourMontliche], function (err) {
            if (err) {
                return res.status(500).json({ error: `Failed to save route: ${err.message}` });
            }
            res.status(201).json({ message: "Route saved successfully", routeId: this.lastID });
        });
    });
});

// Route: Get Routes by Month
app.get("/route/:userId/:month", (req, res) => {
    const { userId, month } = req.params;

    if (!userId || !month) {
        return res.status(400).json({ error: "UserId and month are required" });
    }

    // Calculare date pentru început și sfârșit lună
    const currentYear = new Date().getFullYear();
    const startOfMonth = `${currentYear}-${String(month).padStart(2, '0')}-01`;
    const endOfMonth = `${currentYear}-${String(month).padStart(2, '0')}-31`;

    const query = `
        SELECT * 
        FROM routes 
        WHERE userId = ? 
        AND date BETWEEN ? AND ?
    `;
    db.all(query, [userId, startOfMonth, endOfMonth], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
        }
        res.status(200).json(rows);
    });
});

// Route: Update Password
app.put("/user/password", (req, res) => {
    const { userId, newPassword } = req.body;

    if (!userId || !newPassword) {
        return res.status(400).json({ error: "UserId and newPassword are required" });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, 10);

    const query = `UPDATE users SET password = ? WHERE id = ?`;
    db.run(query, [hashedPassword, userId], function (err) {
        if (err) {
            return res.status(500).json({ error: `Failed to update password: ${err.message}` });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json({ message: "Password updated successfully" });
    });
});

// Route: Export Routes to Excel
app.get("/admin/export", adminOnly, async (req, res) => {
    try {
        // Creare workbook și sheet
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet("Routes");

        // Adaugă header-ul coloanelor
        worksheet.columns = [
            { header: "User ID", key: "userId", width: 15 },
            { header: "Name", key: "name", width: 20 },
            { header: "Date", key: "date", width: 15 },
            { header: "Auto", key: "auto", width: 10 },
            { header: "Tour", key: "tour", width: 10 },
            { header: "Kunde", key: "kunde", width: 10 },
            { header: "Start", key: "start", width: 10 },
            { header: "Ende", key: "ende", width: 10 },
            { header: "Total Monthly Tours", key: "totalTourMontliche", width: 20 },
        ];

        // Obține toate rutele din baza de date
        const query = `SELECT * FROM routes`;
        db.all(query, [], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
            }

            // Adaugă rutele în sheet
            rows.forEach((row) => {
                worksheet.addRow(row);
            });

            // Trimite fișierul Excel pentru descărcare
            res.setHeader(
                "Content-Type",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            );
            res.setHeader("Content-Disposition", "attachment; filename=routes.xlsx");

            return workbook.xlsx.write(res).then(() => res.status(200).end());
        });
    } catch (error) {
        res.status(500).json({ error: `Failed to export routes: ${error.message}` });
    }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
