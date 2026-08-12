// Route auth — vulnérabilités intentionnelles
const express = require('express');
const jwt     = require('jsonwebtoken');
const db      = require('../config/database');
const router  = express.Router();

// ❌ VULN 1 — SQL Injection sur le login
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  // ❌ Concaténation directe → SQLi
  const query = `SELECT * FROM membres WHERE email='${email}' AND password='${password}'`;

  db.get(query, (err, membre) => {
    if (err) return res.status(500).json({ error: err.message, query });
    if (!membre) return res.status(401).json({ error: 'Identifiants invalides' });

    // ❌ VULN 2 — JWT sans expiration + secret faible
    const token = jwt.sign(
      { id: membre.id, email: membre.email, role: membre.role },
      'medilib_jwt_2024'
    );
    res.json({ token, membre: { id: membre.id, email: membre.email } });
  });
});

// ❌ VULN 3 — Inscription sans validation ni hachage MDP
router.post('/register', (req, res) => {
  const { nom, email, password, specialite } = req.body;

  // ❌ MDP stocké en clair + SQLi
  db.run(
    `INSERT INTO membres (nom, email, password, specialite, role)
     VALUES ('${nom}', '${email}', '${password}', '${specialite}', 'membre')`,
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Compte créé', id: this.lastID });
    }
  );
});

module.exports = router;
