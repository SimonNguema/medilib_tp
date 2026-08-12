# MediLib API — TP Récapitulatif DevSecOps
**Cours 2INF2311 — Sécurité Logicielle & DevSecOps**
**SUP de CO Dakar — Master 2 Génie Logiciel**

> ⚠️ **ATTENTION :** Ce code contient des vulnérabilités **intentionnelles** à des fins pédagogiques.

---

## Description

MediLib est une API de gestion de bibliothèque médicale numérique. Elle permet à des professionnels de santé de consulter, emprunter et commenter des ouvrages médicaux spécialisés.

## Architecture

```
MediLib API (Node.js + Express + SQLite)
├── src/
│   ├── server.js        ← Point d'entrée
│   ├── routes/
│   │   ├── auth.js      ← Login / Register
│   │   ├── livres.js    ← Catalogue + Recherche
│   │   ├── emprunts.js  ← Gestion des emprunts
│   │   └── membres.js   ← Profils membres
│   └── config/
│       └── database.js  ← SQLite
└── Dockerfile
```

## Comptes de test

| Email | Mot de passe | Rôle |
|-------|-------------|------|
| admin@medilib.sn | admin2024 | admin |
| diallo@medilib.sn | diallo123 | membre |
| ndiaye@medilib.sn | ndiaye456 | membre |

## Installation

```bash
npm install
npm start
# → http://localhost:3000
```

---

*SUP de CO Dakar — Cours 2INF2311*
