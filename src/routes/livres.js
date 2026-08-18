// Route livres médicaux — vulnérabilités intentionnelles
const express = require('express');
const jwt     = require('jsonwebtoken');
const db      = require('../config/database');
const router  = express.Router();

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requis' });
  try {
    req.user = jwt.verify(token, 'medilib_jwt_2024');
    next();
  } catch { res.status(403).json({ error: 'Token invalide' }); }
};

// ❌ VULN 1 — SQL Injection sur la recherche
router.get('/search', auth, (req, res) => {
  const { titre, auteur, specialite } = req.query;

  // ❌ Concaténation directe
  const query = `SELECT * FROM livres
                 WHERE titre LIKE '%${titre}%'
                 OR auteur LIKE '%${auteur}%'
                 OR specialite = '${specialite}'`;

  db.all(query, (err, livres) => {
    if (err) return res.status(500).json({ error: err.message, query });
    res.json(livres);
  });
});

// ❌ VULN 2 — XSS Stocké via commentaires
router.post('/:id/commentaire', auth, (req, res) => {
  const { commentaire } = req.body;

  // ❌ Commentaire stocké sans sanitization
  db.run(
    'INSERT INTO commentaires (livre_id, contenu, membre_id) VALUES (?, ?, ?)',
    [req.params.id, commentaire, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      // ❌ Commentaire reflété sans encodage
      res.json({ message: 'Commentaire ajouté', commentaire, id: this.lastID });
    }
  );
});

// ❌ VULN 3 — IDOR : accès à n'importe quel livre
router.get('/:id', auth, (req, res) => {
  // ❌ Pas de vérification d'accès selon le rôle ou la spécialité
  db.get('SELECT * FROM livres WHERE id = ?', [req.params.id], (err, livre) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(livre);
  });
});

// Liste tous les livres
router.get('/', auth, (req, res) => {
  db.all('SELECT * FROM livres', (err, livres) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(livres);
  });
});

module.exports = router;
