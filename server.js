require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./database");
const path = require("path");

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

// Verificarea existenței utilizatorului ADMIN la pornirea serverului
const createAdminUser = () => {
    const adminId = "1";
    const adminPassword = "admin2025";
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
app.get("/", (req, res) => res.send("AMC Logistics API is running!"));

// Ruta pentru pagina de login
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

// Ruta pentru autentificare (ID și Parolă)
app.post("/login", (req, res) => {
    const { userId, password } = req.body;
    if (!userId || !password) {
        return res.status(400).json({ error: "UserID and password are required" });
    }

    const query = `SELECT * FROM users WHERE id = ?`;
    db.get(query, [userId], (err, user) => {
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

// Ruta pentru crearea unui utilizator nou (doar admin)
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
app.get("/introducere-ruta", (req, res) => res.sendFile(path.join(__dirname, "public", "introducere-ruta.html")));
app.get("/istoric-rute", (req, res) => res.sendFile(path.join(__dirname, "public", "istoric-rute.html")));
app.get("/mediu-invatare", (req, res) => res.sendFile(path.join(__dirname, "public", "mediu-invatare.html")));
app.get("/plan", (req, res) => res.sendFile(path.join(__dirname, "public", "plan.html")));
app.get("/info", (req, res) => res.sendFile(path.join(__dirname, "public", "info.html")));
app.get("/schimba-parola", (req, res) => res.sendFile(path.join(__dirname, "public", "schimba-parola.html")));

// Pornirea serverului
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    createAdminUser();
});
