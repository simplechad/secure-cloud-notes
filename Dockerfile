# ==========================================
# STAGE 1: Build & Dependencies (Builder Stage)
# ==========================================
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package manifests
COPY package*.json ./

# Install dependencies (only production)
RUN npm install --omit=dev

# ==========================================
# STAGE 2: Production Hardened Image (Runner Stage)
# ==========================================
FROM node:18-alpine AS runner

# Keamanan 1: Set Node Environment ke Production
ENV NODE_ENV=production
ENV PORT=8080

WORKDIR /app

# Keamanan 2: Salin dependensi dari stage builder dengan ownership user 'node'
COPY --chown=node:node package*.json ./
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node ./src ./src

# Keamanan 3: Gunakan user non-root 'node' (bawaan dari image Node Alpine)
USER node

# Keamanan 4: Expose Port
EXPOSE 8080

# Keamanan 5: Healthcheck Kontainer Otomatis
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Eksekusi Aplikasi
CMD ["node", "src/index.js"]
