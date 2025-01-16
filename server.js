require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const ExcelJS = require("exceljs");

const app = express();
const PORT = process.env.PORT || 3000;

// Verifică variabilele de mediu
if (!process.env.JWT_SECRET) {
    console.error("ERROR: JWT_SECRET nu este setat în .env.");
    process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware pentru acces doar de către admini
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

// Ruta principală pentru testarea serverului
app.get("/", (req, res) => {
    res.status(200).send("AMC Logistics API is running!");
});

// Ruta pentru testarea bazei de date
app.get("/test-db", (req, res) => {
    const query = `SELECT name FROM sqlite_master WHERE type='table'`;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: `Database error: ${err.message}` });
        }
        res.json({ tables: rows });
    });
});

// Ruta pentru GET /login
app.get("/login", (req, res) => {
    res.status(200).send("Use POST /login with credentials to authenticate.");
});

// Register Route
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

// Login Route
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

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, userId: user.id, role: user.role });
    });
});

// Save Route
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

// Update Password
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

// Export Routes to Excel
app.get("/admin/export", adminOnly, async (req, res) => {
    try {
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
            { header: "Ende", key: "ende", width: 10 },
            { header: "Total Monthly Tours", key: "totalTourMontliche", width: 20 },
        ];

        const query = `SELECT * FROM routes`;
        db.all(query, [], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: `Failed to fetch routes: ${err.message}` });
            }

            rows.forEach((row) => {
                worksheet.addRow(row);
            });

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

// Pornirea serverului
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
