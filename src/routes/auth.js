// Route auth — vulnérabilités intentionnelles
const express = require('express');
const jwt     = require('jsonwebtoken');
const db      = require('../config/database');
const router  = express.Router();

// ✓ CORRECTION 1 — SQL Injection sur le login (CWE-89 / OWASP A03:2021)
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  // ❌ AVANT — concaténation directe : le payload `admin@medilib.sn' --` commentait
  //    la vérification du mot de passe et connectait l'attaquant en tant qu'admin.
  // const query = `SELECT * FROM membres WHERE email='${email}' AND password='${password}'`;
  // db.get(query, (err, membre) => {
  //   if (err) return res.status(500).json({ error: err.message, query });

  // APRÈS — requête préparée à paramètres liés : le driver SQLite traite email et
  //    password comme des DONNÉES, jamais comme du code SQL. Le payload est cherché
  //    littéralement et ne correspond à aucun compte.
  const query = 'SELECT * FROM membres WHERE email = ? AND password = ?';

  db.get(query, [email, password], (err, membre) => {
    // ✓ La requête SQL n'est plus renvoyée au client : elle exposait le schéma de la
    //   base et confirmait à l'attaquant que son injection atteignait le moteur SQL.
    if (err) return res.status(500).json({ error: 'Erreur serveur' });
    if (!membre) return res.status(401).json({ error: 'Identifiants invalides' });

    // ❌ AVANT — secret de signature en dur + token sans expiration (valable à vie)
    // const token = jwt.sign(
    //   { id: membre.id, email: membre.email, role: membre.role },
    //   'medilib_jwt_2024'
    // );

    // ✓ APRÈS — secret chargé depuis l'environnement + durée de vie limitée à 1h
    const token = jwt.sign(
      { id: membre.id, email: membre.email, role: membre.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
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
