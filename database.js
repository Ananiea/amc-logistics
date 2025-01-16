const sqlite3 = require("sqlite3").verbose();

// Conectarea la baza de date (sau crearea acesteia dacă nu există)
const db = new sqlite3.Database("./amc-logistics.db", (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        console.log("Connected to SQLite database.");
    }
});

// Crearea tabelelor (dacă nu există deja)
db.serialize(() => {
    // Tabelul pentru utilizatori
    db.run(
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'courier'
        )`
    );

    // Tabelul pentru rute
    db.run(
        `CREATE TABLE IF NOT EXISTS routes (
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
            FOREIGN KEY (userId) REFERENCES users(id)
        )`
    );
});

module.exports = db;
