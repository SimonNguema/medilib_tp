// MediLib API — Bibliothèque médicale numérique
// TP Récapitulatif DevSecOps — SUP de CO Dakar
// ⚠️  Vulnérabilités intentionnelles à des fins pédagogiques

const express = require('express');
const dotenv  = require('dotenv');
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ❌ VULN 1 — Pas de headers de sécurité (helmet manquant)

// ❌ VULN 2 — Secrets hardcodés
const JWT_SECRET     = "medilib_jwt_2024";
const ADMIN_TOKEN    = "ml_admin_tok3n_secret";
const DB_ENCRYPTION  = "dbK3yMediLib!";

// ❌ VULN 3 — CORS permissif
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// Routes
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/livres',  require('./routes/livres'));
app.use('/api/emprunts',require('./routes/emprunts'));
app.use('/api/membres', require('./routes/membres'));

// ❌ VULN 4 — Stack trace en production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    path:  __filename,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MediLib démarré sur le port ${PORT}`));
module.exports = app;
