require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Configuration
const db = new Pool({
    host: process.env.PG_HOST || "localhost",
    user: process.env.PG_USER || "amc_user",
    password: process.env.PG_PASSWORD || "securepassword",
    database: process.env.PG_DATABASE || "amc_logistics",
    port: process.env.PG_PORT || 5432,
    ssl: { rejectUnauthorized: false },
});

// Test PostgreSQL Connection
db.connect()
    .then(() => console.log("Conectat la baza de date PostgreSQL!"))
    .catch((err) => {
        console.error("Eroare la conectarea cu baza de date:", err);
        process.exit(1);
    });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Middleware pentru acces doar de admin
function adminOnly(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ error: "Neautorizat: Token lipsă" });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "admin") {
            return res.status(403).json({ error: "Acces interzis: Doar pentru admin" });
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token invalid" });
    }
}

// Ruta principală pentru testarea serverului
app.get("/", (req, res) => {
    res.status(200).send("AMC Logistics API este activ!");
});

// Ruta pentru login
app.post("/login", async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ error: "ID și parola sunt necesare" });
    }

    const query = "SELECT * FROM users WHERE id = $1";
    const { rows } = await db.query(query, [userId]);

    if (rows.length === 0) {
        return res.status(401).json({ error: "Informații de autentificare invalide" });
    }

    const user = rows[0];
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: "Informații de autentificare invalide" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, userId: user.id, role: user.role, name: user.name });
});

// Ruta pentru crearea de utilizatori în bulk (CSV)
const upload = multer({ dest: "uploads/" });

app.post("/admin/bulk-users", adminOnly, upload.single("file"), async (req, res) => {
    const filePath = req.file.path;

    try {
        const data = fs.readFileSync(filePath, "utf8");
        const lines = data.split("\n");

        for (const line of lines) {
            const [name, id, password, email, phone] = line.split(",");
            const hashedPassword = bcrypt.hashSync(password.trim(), 10);

            const query = `
                INSERT INTO users (name, id, password, email, phone, role)
                VALUES ($1, $2, $3, $4, $5, 'courier')
            `;
            await db.query(query, [name.trim(), id.trim(), hashedPassword, email.trim(), phone.trim()]);
        }

        res.status(200).json({ message: "Utilizatorii au fost creați cu succes!" });
    } catch (error) {
        console.error("Eroare la procesarea fișierului CSV:", error);
        res.status(500).json({ error: "Eroare la procesarea fișierului CSV" });
    } finally {
        fs.unlinkSync(filePath);
    }
});

// Pornirea serverului
app.listen(PORT, () => console.log(`Serverul rulează pe portul ${PORT}`));
