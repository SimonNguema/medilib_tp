// Route membres — vulnérabilités intentionnelles
const express = require('express');
const jwt     = require('jsonwebtoken');
const db      = require('../config/database');
const router  = express.Router();

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requis' });
  try {
    // Correction 2 : secret lu depuis l'environnement, cohérent avec jwt.sign (auth.js)
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(403).json({ error: 'Token invalide' }); }
};

// ❌ VULN 1 — Exposition MDP + données sensibles à tout membre connecté
router.get('/', auth, (req, res) => {
  // ❌ Pas de vérification du rôle admin
  db.all(
    'SELECT id, nom, email, password, specialite, role FROM membres',
    (err, membres) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(membres); // ❌ Expose les MDP en clair !
    }
  );
});

// ❌ VULN 2 — IDOR : accès au profil complet de n'importe quel membre
router.get('/:id', auth, (req, res) => {
  db.get('SELECT * FROM membres WHERE id = ?', [req.params.id], (err, membre) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(membre);
  });
});

// ❌ VULN 3 — Mass Assignment : mise à jour sans whitelist
router.put('/:id', auth, (req, res) => {
  const updates = req.body;
  // ❌ Un membre peut se promouvoir admin via role:'admin'
  const fields = Object.keys(updates)
    .map(k => `${k}='${updates[k]}'`)
    .join(', ');

  db.run(
    `UPDATE membres SET ${fields} WHERE id = ${req.params.id}`,
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Profil mis à jour', changes: this.changes });
    }
  );
});

module.exports = router;
