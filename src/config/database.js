const sqlite3 = require('sqlite3').verbose();
const path    = require('path');

const db = new sqlite3.Database(
  path.join(__dirname, '../../medilib.db'),
  (err) => {
    if (err) console.error(err.message);
    else { console.log('Connecté à SQLite — MediLib'); initDatabase(); }
  }
);

function initDatabase() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS membres (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      nom        TEXT NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      specialite TEXT,
      role       TEXT DEFAULT 'membre',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS livres (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      titre      TEXT NOT NULL,
      auteur     TEXT NOT NULL,
      specialite TEXT,
      isbn       TEXT,
      disponible INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS emprunts (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      livre_id    INTEGER NOT NULL,
      membre_id   INTEGER NOT NULL,
      date_retour TEXT,
      statut      TEXT DEFAULT 'en_cours',
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS commentaires (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      livre_id   INTEGER NOT NULL,
      contenu    TEXT NOT NULL,
      membre_id  INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Données de test — MDP en clair intentionnellement
    db.run(`INSERT OR IGNORE INTO membres (nom, email, password, specialite, role)
            VALUES ('Admin', 'admin@medilib.sn', 'admin2024', 'Administration', 'admin')`);
    db.run(`INSERT OR IGNORE INTO membres (nom, email, password, specialite, role)
            VALUES ('Dr. Diallo', 'diallo@medilib.sn', 'diallo123', 'Cardiologie', 'membre')`);
    db.run(`INSERT OR IGNORE INTO membres (nom, email, password, specialite, role)
            VALUES ('Dr. Ndiaye', 'ndiaye@medilib.sn', 'ndiaye456', 'Neurologie', 'membre')`);

    db.run(`INSERT OR IGNORE INTO livres (titre, auteur, specialite, isbn)
            VALUES ('Cardiologie Clinique', 'Pr. Mbaye', 'Cardiologie', '978-2-10-001')`);
    db.run(`INSERT OR IGNORE INTO livres (titre, auteur, specialite, isbn)
            VALUES ('Neurologie Pratique', 'Pr. Fall', 'Neurologie', '978-2-10-002')`);
    db.run(`INSERT OR IGNORE INTO livres (titre, auteur, specialite, isbn)
            VALUES ('Pharmacologie Générale', 'Dr. Sow', 'Pharmacologie', '978-2-10-003')`);
  });
}

module.exports = db;
