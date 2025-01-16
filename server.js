require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const ExcelJS = require("exceljs");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

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

// Servirea fișierelor HTML pentru pagini
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/admin-create-user", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-create-user.html"));
});

app.get("/info", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "info.html"));
});

app.get("/introducere-ruta", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "introducere-ruta.html"));
});

app.get("/istoric-rute", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "istoric-rute.html"));
});

app.get("/mediu-invatare", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "mediu-invatare.html"));
});

app.get("/plan", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "plan.html"));
});

app.get("/profile", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get("/schimba-parola", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "schimba-parola.html"));
});

// Endpoint pentru încărcarea unui fișier CSV
app.post("/admin/bulk-upload", adminOnly, upload.single("file"), async (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: "No file uploaded" });
    }

    const filePath = path.join(__dirname, file.path);
    const fileStream = fs.createReadStream(filePath);

    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
    });

    let successCount = 0;
    let errorCount = 0;
    const errors = [];

    for await (const line of rl) {
        const [name, id, password, email, phone] = line.split(",");
        if (!name || !id || !password || !email || !phone) {
            errors.push(`Invalid data: ${line}`);
            errorCount++;
            continue;
        }

        const hashedPassword = bcrypt.hashSync(password.trim(), 10);

        const query = `INSERT INTO users (id, name, email, phone, password, role) VALUES (?, ?, ?, ?, ?, 'courier')`;
        db.run(query, [id.trim(), name.trim(), email.trim(), phone.trim(), hashedPassword], (err) => {
            if (err) {
                errors.push(`Error adding user ${id.trim()}: ${err.message}`);
                errorCount++;
            } else {
                successCount++;
            }
        });
    }

    rl.on("close", () => {
        fs.unlinkSync(filePath); // Șterge fișierul încărcat după procesare
        res.json({
            message: "Upload completed",
            successCount,
            errorCount,
            errors,
        });
    });
});

// Pornire server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
