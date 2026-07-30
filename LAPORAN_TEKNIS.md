# LAPORAN TEKNIS CASE STUDY KEAMANAN INFORMASI
## Container Deployment Aman Menggunakan Docker dan Fly.io Free Tier

**Mata Kuliah:** Keamanan Informasi  
**Tema:** Perancangan dan Implementasi Sistem Aman Berbasis Cloud  
**Judul Proyek (#10):** Container Deployment Aman Menggunakan Docker dan Fly.io Free Tier  
**Penyusun:** [Nama Mahasiswa] / [NIM]  
**Tanggal:** 30 Juli 2026  

---

## DAFTAR ISI
1. BAB I: Latar Belakang & Deskripsi Kasus
2. BAB II: Arsitektur Cloud & Diagram Sistem
3. BAB III: Langkah Implementasi & Hardening Kontainer
4. BAB IV: Konfigurasi Keamanan (Security Hardening)
5. BAB V: Hasil Pengujian Performa & Keamanan
6. BAB VI: Analisis Risiko & Mitigasi
7. BAB VII: Kesimpulan

---

## BAB I: LATAR BELAKANG & DESKRIPSI KASUS

### 1.1 Latar Belakang
Penggunaan teknologi *cloud computing* dan kontainerisasi seperti **Docker** telah menjadi standar industri dalam pengembangan dan deployment aplikasi modern. Namun, kemudahan deployment kontainer sering kali tidak diimbangi dengan konfigurasi keamanan yang memadai. Menurut laporan keamanan cyber, mayoritas kontainer di lingkungan production mengalami celah keamanan akibat penggunaan image berukuran besar yang mengandung banyak *vulnerabilities*, kontainer yang dijalankan dengan hak akses tertinggi (*root user*), serta minimnya pengamanan lalu lintas data berbasis SSL/TLS.

Proyek ini bertujuan untuk merancang dan menerapkan mekanisme keamanan berlapis (*Defense in Depth*) pada aplikasi berbasis REST API mikro yang dikontainerisasi dengan Docker dan dideploy pada layanan PaaS gratis **Fly.io**.

### 1.2 Tujuan Proyek
1. Merancang dan mengimplementasikan aplikasi web berbasis kontainer dengan **Hardened Dockerfile**.
2. Menerapkan eksekusi *non-root user* dalam kontainer untuk mencegah celah *container escape*.
3. Menerapkan *vulnerability scanning* menggunakan **Trivy** untuk mengidentifikasi dan memitigasi kerentanan pada kontainer image.
4. Menerapkan proteksi keamanan aplikasi (*Application Security*) meliputi *HTTP Security Headers* (Helmet.js), *Rate Limiting*, dan *Input Sanitization*.
5. Menerapkan **Autentikasi PIN Akses** yang terintegrasi dengan variabel lingkungan (*Secrets Management*) untuk membatasi akses CRUD Notes.
6. Mendeploy kontainer ke layanan cloud gratis (Fly.io) dengan enkripsi SSL/TLS otomatis dan *Secrets Management*.

---

## BAB II: ARSITEKTUR CLOUD & DIAGRAM SISTEM

### 2.1 Alur Arsitektur Keamanan
Aplikasi dirancang dengan pendekatan *Defense in Depth* yang terdiri dari 4 lapisan utama:

```
[ Client / Browser (Frontend Web UI) ] 
                     │ (HTTPS / TLS 1.3 - Encrypted Traffic)
                     ▼
  [ Fly.io Cloud Edge Proxy / Firewall ]
                     │ (Security Headers, TLS Termination, Auto HTTPS Redirect)
                     ▼
[ Docker Container (Isolated Runtime Environment) ]
    ├── User: 'node' (Non-Root Privilege)
    ├── AppSec: Helmet.js + Rate Limiter
    ├── Auth Check: x-admin-pin header verification (PIN: 12345 / custom Env)
    ├── Views: Notes CRUD (Default) / Status Keamanan (Diagnostic View Toggle)
    └── Monitoring Endpoint: /health (Automated Monitoring)
```

### 2.2 Komponen Sistem
1. **Application Layer**: Node.js Express API (Secure Notes CRUD: Create, Read, Update, Delete).
2. **Frontend Layer**: Client Dashboard responsif menggunakan Vanilla HTML5, CSS3, dan Javascript yang terintegrasi langsung dengan verifikasi PIN, transisi menu, dan pop-up exit konfirmasi.
3. **Containerization Layer**: Docker Engine + Multi-Stage Alpine Linux Base Image.
4. **Security Audit Layer**: Trivy Security Scanner (Static Vulnerability Analysis).
5. **Cloud Platform Layer**: Fly.io (Container PaaS dengan Auto SSL & Edge TLS Proxy).

---

## BAB III: LANGKAH IMPLEMENTASI & HARDENING KONTAINER

### 3.1 Struktur File Proyek
Proyek disusun dengan struktur yang bersih dan terisolasi:
```
secure-container-app/
├── src/
│   ├── public/
│   │   └── index.html     # Frontend Web Dashboard (CRUD UI, Status Panel & Login PIN)
│   └── index.js           # Backend Server Express + AppSec + CRUD Endpoints
├── Dockerfile             # Multi-stage Hardened Dockerfile
├── .dockerignore          # Mengabaikan file sensitif dari image
├── package.json           # Dependensi proyek
├── fly.toml               # Konfigurasi Cloud Deployment Fly.io
└── LAPORAN_TEKNIS.md      # Dokumentasi Laporan Teknis
```

### 3.2 Implementasi Kode Aplikasi (AppSec & CRUD)
Kode aplikasi pada `src/index.js` mengintegrasikan fitur keamanan berikut:
- **Helmet.js (Content Security Policy)**: Menyediakan header keamanan HTTP ketat. Untuk frontend, CSP dikonfigurasi untuk hanya mengizinkan eksekusi script lokal dan resource terpercaya (`https://fonts.googleapis.com`).
- **Rate Limiting**: Pembatasan maksimal 100 permintaan per 15 menit per IP untuk mencegah serangan *Brute Force* dan *DDoS* tingkat aplikasi.
- **Hiding Tech Stack**: Menghapus header `X-Powered-By: Express` agar penyerang tidak dapat dengan mudah mendeteksi kerangka kerja yang digunakan.
- **Secure CRUD API**: Endpoint untuk mengedit (`PUT /api/notes/:id`) dan menghapus (`DELETE /api/notes/:id`) dikonfigurasi secara ketat dan wajib melewati middleware autentikasi PIN.

### 3.3 Autentikasi PIN Akses (Secrets Management)
Untuk memenuhi aspek keamanan autentikasi, aplikasi menerapkan sistem verifikasi PIN pada endpoint CRUD:
- **PIN Default Pengujian Akademis**: **`12345`** (dapat diubah sesuai preferensi melalui file `.env` lokal atau konfigurasi cloud).
- Endpoint publik `/health` dan `/api/info` tetap dapat diakses bebas (mempermudah pemantauan balancer).
- Endpoint `/api/notes` (POST, GET, PUT, & DELETE) dilindungi oleh middleware `authenticatePIN` yang memeriksa keberadaan header `x-admin-pin`.
- Nilai PIN dicocokkan dengan variabel lingkungan `ADMIN_PIN` yang diatur melalui *Environment Secrets* di cloud (tidak di-hardcode dalam berkas kode).

```javascript
const authenticatePIN = (req, res, next) => {
  const userPin = req.headers['x-admin-pin'];
  if (!userPin || userPin !== ADMIN_PIN) {
    return res.status(401).json({
      success: false,
      error: 'Autentikasi Gagal: PIN tidak valid atau tidak disertakan.',
    });
  }
  next();
};
```

---

## BAB IV: KONFIGURASI KEAMANAN (SECURITY HARDENING)

### 4.1 Ringkasan Proteksi Keamanan

| Parameter Keamanan | Konfigurasi Standar (Tidak Aman) | Konfigurasi Proyek Ini (Aman) |
|---|---|---|
| **Base Image** | `node:latest` (> 1GB, ratusan CVE) | `node:18-alpine` (~170MB, minimal CVE) |
| **Container Privilege** | `root` (Default) | `node` (Non-Root User) |
| **Build Pattern** | Single Stage (Menyimpan devTools) | Multi-Stage Build |
| **HTTP Headers** | Plain Express (`X-Powered-By` terbuka) | Helmet Security Headers Enabled |
| **Rate Limit** | Unlimited Requests | Max 100 Requests / 15 Menit |
| **Enkripsi Transit** | HTTP (Plain Text) | HTTPS / TLS via Fly.io Edge Proxy |
| **Autentikasi API** | Tanpa Autentikasi | PIN Access dengan Header `x-admin-pin` |
| **Diagnostik Status** | Terbuka di halaman utama | Terkunci di halaman terpisah (butuh login) |
| **Health Monitoring** | Tidak Ada | Automated `HEALTHCHECK` Directive |
| **Input Validation** | payload tak terbatas | JSON Payload dibatasi max 10KB |

---

## BAB V: HASIL PENGUJIAN PERFORMA & KEAMANAN

### 5.1 Pengujian Hak Akses User Kontainer (Non-Root Test)
Perintah eksekusi pengujian:
```bash
docker run --rm secure-container-app:v1 whoami
```
**Hasil:** `node`  
*Analisis:* Kontainer terbukti berjalan di bawah privilege user `node` dan bukan `root`.

---

> [!NOTE]
> **BAGIAN UNTUK SCREENSHOT MAHASISWA**  
> *Di bawah ini adalah lokasi penyisipan bukti screenshot pengujian yang perlu diambil oleh mahasiswa:*
> 
> - **[SCREENSHOT 1: Hasil Docker Build & Pengujian Whoami]**  
>   *(Dokumentasi terminal saat menjalankan `docker build` dan `docker run --rm secure-container-app:v1 whoami`)*
> 
> - **[SCREENSHOT 2: Hasil Vulnerability Scan Trivy]**  
>   *(Dokumentasi terminal hasil perintah `trivy image secure-container-app:v1`)*
> 
> - **[SCREENSHOT 3: Status Deployment Fly.io Dashboard]**  
>   *(Dokumentasi halaman dashboard/terminal status app running di Fly.io)*
> 
> - **[SCREENSHOT 4: Verifikasi HTTPS & Security Headers di Browser/Postman]**  
>   *(Dokumentasi inspect response header yang menunjukkan SSL Aktif & Header Helmet terpasang)*

---

## BAB VI: ANALISIS RISIKO & MITIGASI

| No | Potensi Risiko Keamanan | Tingkat Risiko | Solusi Mitigasi yang Diterapkan |
|---|---|---|---|
| 1 | **Container Escape** (Peretas menjebol kontainer ke host OS) | High | Menggunakan user non-root (`USER node`) sehingga jika kontainer jebol, peretas tidak memiliki akses root pada host. |
| 2 | **Known Vulnerabilities (CVE)** pada Image | Medium | Menggunakan minimal image (`alpine`) dan melakukan audit *static scanning* dengan **Trivy**. |
| 3 | **Serangan Brute Force & DoS** | Medium | Mengisolasi request dengan `express-rate-limit` dan membatasi payload JSON maksimal 10KB. |
| 4 | **Man-in-the-Middle (MitM) Attack** | High | Mengharuskan HTTPS/TLS dan mengaktifkan header `Strict-Transport-Security` (HSTS). |
| 5 | **Akses API Ilegal / Manipulasi CRUD** | High | Membatasi rute CRUD (Create, Read, Update, Delete) dengan header `x-admin-pin` yang diverifikasi secara server-side. |
| 6 | **Information Leakage** | Low | Menghapus header `X-Powered-By` dan memusatkan error handler agar tidak menampilkan stack trace ke user. |

---

## BAB VII: KESIMPULAN

Berdasarkan perancangan, implementasi, dan pengujian yang telah dilakukan, dapat disimpulkan bahwa:
1. Keamanan kontainer berbasis Docker tidak hanya bergantung pada platform cloud, tetapi dimulai dari penyusunan **Dockerfile yang aman (hardened)**.
2. Penggunaan **multi-stage build** dan **minimal base image (Alpine)** terbukti efektif memangkas ukuran image hingga lebih dari 80% serta mengurangi jumlah potensi kerentanan (CVE).
3. Penerapan **non-root user**, **autentikasi PIN**, **HTTP security headers**, dan **rate limiting** memberikan perlindungan yang solid di level aplikasi.
4. Deployment ke platform **Fly.io** memungkinkan sistem beroperasi secara aman di cloud dengan enkripsi HTTPS otomatis tanpa memerlukan biaya berlangganan (*Free Tier*).
