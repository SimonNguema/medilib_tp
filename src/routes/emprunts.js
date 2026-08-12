// Route emprunts — vulnérabilités intentionnelles
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

// ❌ VULN 1 — IDOR : accès aux emprunts de n'importe quel membre
router.get('/membre/:membreId', auth, (req, res) => {
  // ❌ Pas de vérification que membreId === req.user.id
  db.all(
    'SELECT * FROM emprunts WHERE membre_id = ?',
    [req.params.membreId],
    (err, emprunts) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(emprunts);
    }
  );
});

// ❌ VULN 2 — Tampering : date de retour modifiable par le client
router.post('/emprunter', auth, (req, res) => {
  const { livreId, dateRetour } = req.body;
  // ❌ dateRetour vient du client — peut être modifiée arbitrairement

  const query = `INSERT INTO emprunts (livre_id, membre_id, date_retour, statut)
                 VALUES ('${livreId}', '${req.user.id}', '${dateRetour}', 'en_cours')`;

  db.run(query, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Emprunt créé', id: this.lastID, dateRetour });
  });
});

// ❌ VULN 3 — Repudiation : retour de livre sans log d'audit
router.put('/:id/retourner', auth, (req, res) => {
  // ❌ Aucune trace : qui a retourné, quand, état du livre
  db.run(
    `UPDATE emprunts SET statut='retourné' WHERE id=${req.params.id}`,
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Livre retourné', id: req.params.id });
    }
  );
});

module.exports = router;
