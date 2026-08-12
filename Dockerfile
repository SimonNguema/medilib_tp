# ⚠️  Dockerfile NON sécurisé — vulnérabilités intentionnelles

# ❌ Image non spécifique
FROM node:18

# ❌ Exécution en root
WORKDIR /app
COPY . .
RUN npm install

# ❌ Secret dans l'image
ENV JWT_SECRET="medilib_jwt_2024"
ENV ADMIN_TOKEN="ml_admin_tok3n_secret"

# ❌ Port debug exposé
EXPOSE 3000
EXPOSE 9229

CMD ["node", "src/server.js"]
