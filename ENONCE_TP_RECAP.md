# TP RÉCAPITULATIF — Sécurisation de MediLib
**Module :** Sécurité Logicielle & DevSecOps (2INF2311)
**SUP de CO Dakar — Master 2 Génie Logiciel**
**Durée :** 2 heures | **Documents autorisés :** cours + notes

---

## Contexte

**MediLib** est une API de gestion de bibliothèque médicale numérique permettant à des professionnels de santé de consulter, emprunter et commenter des ouvrages spécialisés.

Le développeur a livré le code sans aucune analyse de sécurité. Votre mission : appliquer la chaîne complète DevSecOps — du Threat Modeling à la pipeline automatisée.

**Repo :** à forker depuis l'URL fournie par l'enseignant.

---

## Partie 1 — Threat Modeling (sur papier)

### Architecture MediLib

```
[Médecin / Pharmacien]
         |
         | HTTPS
         ↓
[API Gateway]  ←→  [Attaquant externe]
         |
    ┌────┴────┐
    ↓         ↓
[API MediLib]  [Frontend Web]
    |
    ├── [SQLite BDD]
    └── [Système de fichiers / PDF]
```

**Q1.1** — Sur votre feuille, dessinez le DFD complet de MediLib en ajoutant :
- Les frontières de confiance (au minimum 2)
- Les flux de données entre chaque composant
- Le type de données qui circule sur chaque flux

**Q1.2** — Appliquez STRIDE sur le flux **Médecin → API MediLib**. Complétez le tableau :

| Catégorie STRIDE | Menace concrète sur ce flux | Contre-mesure |
|-----------------|----------------------------|---------------|
| Spoofing | | |
| Tampering | | |
| Repudiation | | |
| Information Disclosure | | |
| Denial of Service | | |
| Elevation of Privilege | | |

**Q1.3** — Dans `src/routes/emprunts.js`, la route `PUT /:id/retourner` a une menace de **Repudiation**. Expliquez en 3 lignes pourquoi et proposez une correction.

---

## Partie 2 — Analyse OWASP Top 10

### Q2.1 — Identification des vulnérabilités

Lisez le code source et remplissez le tableau suivant avec au moins **6 vulnérabilités** :

| Fichier | Ligne | Vulnérabilité | Catégorie OWASP | Sévérité |
|---------|-------|--------------|-----------------|----------|
| | | | | |

### Q2.2 — Exploitation SQLi

Dans `src/routes/auth.js`, rédigez le payload exact pour se connecter en tant qu'`admin@medilib.sn` sans connaître le mot de passe :

```
Email    : ___________________________
Password : ___________________________
```

Expliquez en 2 lignes pourquoi ce payload fonctionne.

### Q2.3 — XSS Stocké

Dans `src/routes/livres.js`, la route `POST /:id/commentaire` est vulnérable au XSS Stocké.

Rédigez le payload JavaScript malveillant qui volerait le token JWT de tous les médecins qui lisent les commentaires du livre :

```javascript
// Votre payload :
```

### Q2.4 — Mass Assignment

Dans `src/routes/membres.js`, la route `PUT /:id` est vulnérable au Mass Assignment.

Rédigez la requête curl qui permettrait à un membre de se promouvoir administrateur :

```bash
curl -X PUT http://localhost:3000/api/membres/2 \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '____________________________'
```

---

## Partie 3 — Règles Semgrep Custom

Créez le fichier `.semgrep/rules.yaml` avec **3 règles** qui détectent les vulnérabilités de MediLib.

**Contraintes :**
- Règle 1 : doit détecter la SQL Injection dans les routes (concaténation directe)
- Règle 2 : doit détecter les secrets hardcodés dans `server.js`
- Règle 3 : au choix parmi les autres vulnérabilités identifiées

Chaque règle doit avoir : `id`, `pattern`, `message`, `languages`, `severity`, `metadata.cwe`

---

## Partie 4 — Pipeline GitHub Actions

Créez le fichier `.github/workflows/devsecops.yml` avec les jobs suivants :

```
SAST (Semgrep) → SCA (Trivy) → Build Docker → Scan Image → Summary
```

**Exigences :**
- Les résultats SAST et SCA uploadés en SARIF dans GitHub Security
- Le job Build ne se déclenche que si SAST et SCA passent
- Trivy image scan avec `ignore-unfixed: true`
- Un job `security-summary` avec tableau récapitulatif

**Q4.1** — Sur quel job mettriez-vous `exit-code: '1'` en priorité dans un contexte médical ? Justifiez en 2 lignes.

---

## Partie 5 — Corrections

Corrigez les **2 vulnérabilités suivantes** et poussez sur GitHub :

**Correction 1 — SQLi dans `src/routes/auth.js` (login)**

```javascript
// ❌ AVANT
const query = `SELECT * FROM membres WHERE email='${email}' AND password='${password}'`;

// ✓ APRÈS — à compléter
const query = _________________________;
db.get(query, _________________________, (err, membre) => { ... });
```

**Correction 2 — Secret hardcodé dans `src/server.js`**

```javascript
// ❌ AVANT
const JWT_SECRET = "medilib_jwt_2024";

// ✓ APRÈS — à compléter
const JWT_SECRET = _________________________;
```

Après correction → pusher → vérifier que les alertes passent en **Fixed** dans Security tab.

---

## Livrables

1. **Lien du repo GitHub** avec pipeline active
2. **`.semgrep/rules.yaml`** avec 3 règles
3. **Screenshot Security tab** avec les alertes
4. **Feuille réponses** pour les parties 1 et 2 (sur papier)

---

*SUP de CO Dakar — Cours 2INF2311*
