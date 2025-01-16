require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const ExcelJS = require("exceljs");
const path = require("path");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware pentru verificarea rolului de admin
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

// Creare utilizator admin la pornirea serverului
const createAdminUser = () => {
    const adminId = "1";
    const adminPassword = "24091997";
    const hashedPassword = bcrypt.hashSync(adminPassword, 10);
    const query = `INSERT OR IGNORE INTO users (id, name, email, phone, password, role) VALUES (?, 'Admin', 'admin@amlogistics.com', '0000000000', ?, 'admin')`;
    db.run(query, [adminId, hashedPassword], (err) => {
        if (err) {
            console.error("Error creating admin user:", err.message);
        } else {
            console.log("Admin user verified/created successfully.");
        }
    });
};

// Ruta principală pentru testarea serverului
app.get("/", (req, res) => res.send("AM Logistics API is running!"));

// Ruta pentru descărcarea fișierului Excel
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

// Ruta pentru crearea utilizatorilor noi (admin only)
app.post("/admin/create-user", adminOnly, (req, res) => {
    const { userId, name, password, email, phone } = req.body;
    if (!userId || !name || !password || !email || !phone) {
        return res.status(400).json({ error: "All fields are required" });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const query = `INSERT INTO users (id, name, email, phone, password, role) VALUES (?, ?, ?, ?, ?, 'courier')`;
    db.run(query, [userId, name, email, phone, hashedPassword], (err) => {
        if (err) {
            if (err.message.includes("UNIQUE constraint")) {
                return res.status(400).json({ error: "UserID already in use" });
            }
            return res.status(500).json({ error: `Failed to create user: ${err.message}` });
        }
        res.status(201).json({ message: "User created successfully" });
    });
});

// Rutele pentru alte pagini
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/admin-create-user", (req, res) => res.sendFile(path.join(__dirname, "public", "admin-create-user.html")));

app.post("/upload-plan", upload.single("file"), (req, res) => {
    const { title } = req.body;
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: "Kein Datei hochgeladen (Niciun fișier încărcat)" });
    }

    const filePath = `/uploads/${file.filename}`;
    res.status(200).json({ title, link: filePath });
});

// Pornirea serverului
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    createAdminUser();
});
