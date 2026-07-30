# Secure Cloud Notes & Health Check API 🔒🐳

Proyek Case Study Mata Kuliah Keamanan Informasi: **Container Deployment Aman Menggunakan Docker dan Fly.io Free Tier** (Judul #10).

## 📌 Deskripsi Proyek
Aplikasi ini adalah REST API mikro berbasis Node.js (Express) yang mengimplementasikan arsitektur kontainerisasi aman (Docker Hardening) dan dideploy ke layanan cloud gratis dengan pengamanan berlapis (Defense in Depth).

## 🛡️ Fitur Keamanan Berlapis (Security Implementation)
1. **Container Hardening**:
   - Base Image Minimal (`node:18-alpine`).
   - Multi-Stage Build untuk memisahkan instruksi build & runtime.
   - **Non-Root Execution**: Aplikasi berjalan di bawah user non-privileged (`USER node`).
   - Automated Container `HEALTHCHECK`.
2. **Application Security (AppSec)**:
   - **Helmet.js**: Perlindungan HTTP Security Headers (HSTS, CSP, X-Frame-Options `DENY`, X-Content-Type-Options `nosniff`).
   - **Rate Limiting**: Mencegah serangan Brute Force & DoS ringan (`express-rate-limit`).
   - **Input Sanitization & Validation**: Membatasi ukuran payload JSON (max 10KB) & validasi tipe data.
   - **Hiding Tech Stack**: Menghapus header `X-Powered-By`.
3. **Cloud Infrastructure Security**:
   - Automatic HTTP to HTTPS redirection (Enkripsi TLS/SSL saat transit).
   - Cloud Environment Secrets Management (tanpa hardcoded credentials).

## 🚀 Cara Menjalankan Secara Lokal (Local Docker)

### 1. Build Docker Image:
```bash
docker build -t secure-container-app:v1 .
```

### 2. Verifikasi Non-Root User:
```bash
docker run --rm secure-container-app:v1 whoami
# Output harus: node (BUKAN root)
```

### 3. Menjalankan Kontainer:
```bash
docker run -d -p 8080:8080 --name secure-app secure-container-app:v1
```

Akses aplikasi di browser atau curl:
- Root Info: `http://localhost:8080/`
- Healthcheck: `http://localhost:8080/health`
- Notes API: `http://localhost:8080/api/notes`

---

## 🔍 Vulnerability Scanning (Trivy Audit)
Jalankan pengujian celah keamanan kontainer dengan [Trivy](https://aquasecurity.github.io/trivy/):
```bash
trivy image secure-container-app:v1
```

---

## ☁️ Deployment ke Fly.io
1. Install Fly.io CLI (`flyctl`).
2. Login ke akun Fly.io: `fly auth login`
3. Launch & Deploy:
   ```bash
   fly launch
   fly deploy
   ```
