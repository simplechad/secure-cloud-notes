const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Default Admin PIN jika tidak diset di env
const ADMIN_PIN = process.env.ADMIN_PIN || '12345';

// 1. KEAMANAN: HTTP Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
  })
);

app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

// 2. KEAMANAN: Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // Menaikkan limit sedikit untuk mendukung operasi CRUD & Status
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Terlalu banyak permintaan dari IP ini. Silakan coba lagi setelah 15 menit.',
  },
});

app.use('/api/', apiLimiter);

// Serve Frontend Static Files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware Autentikasi PIN
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

// In-Memory Storage dengan ID Auto-Increment
let notes = [
  { id: 1, title: 'Tips Keamanan Kontainer', content: 'Selalu gunakan user non-root (USER node) di dalam Dockerfile Anda untuk menghindari privilege escalation.', createdAt: new Date() },
  { id: 2, title: 'HTTP Headers', content: 'HelmetJS membantu mengamankan Express app dengan menyetel berbagai HTTP headers secara otomatis.', createdAt: new Date() }
];
let nextId = 3;

// Endpoint API Info (Public)
app.get('/api/info', (req, res) => {
  res.json({
    name: 'Secure Cloud Notes API',
    status: 'Active',
    environment: NODE_ENV,
    securityFeatures: [
      'HTTPS/TLS Enabled',
      'Helmet HTTP Security Headers',
      'Rate Limiting Protection',
      'Non-Root Docker Execution',
      'PIN Authentication',
      'Container Healthcheck Monitoring',
      'Full CRUD Capabilities'
    ],
    timestamp: new Date(),
  });
});

// Endpoint Verifikasi PIN
app.post('/api/auth/verify', (req, res) => {
  const { pin } = req.body;
  if (!pin) {
    return res.status(400).json({ success: false, error: 'PIN wajib diisi.' });
  }
  if (pin === ADMIN_PIN) {
    return res.json({ success: true, message: 'Autentikasi berhasil.' });
  }
  res.status(401).json({ success: false, error: 'PIN yang Anda masukkan salah.' });
});

// Endpoint Healthcheck (Public)
app.get('/health', (req, res) => {
  res.status(200).json({
    uptime: process.uptime(),
    message: 'OK',
    status: 'HEALTHY',
    timestamp: new Date(),
    memoryUsage: process.memoryUsage(),
  });
});

// ==========================================
// OPERASI CRUD AMAN (PROTECTED BY PIN)
// ==========================================

// 1. Read All Notes
app.get('/api/notes', authenticatePIN, (req, res) => {
  res.json({
    success: true,
    count: notes.length,
    data: notes,
  });
});

// 2. Create Note
app.post('/api/notes', authenticatePIN, (req, res) => {
  const { title, content } = req.body;

  if (!title || !content || typeof title !== 'string' || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Title dan Content wajib diisi dengan format string.',
    });
  }

  const newNote = {
    id: nextId++,
    title: title.trim().substring(0, 100),
    content: content.trim().substring(0, 500),
    createdAt: new Date(),
  };

  notes.push(newNote);
  res.status(201).json({
    success: true,
    message: 'Catatan berhasil disimpan.',
    data: newNote,
  });
});

// 3. Update Note (Edit)
app.put('/api/notes/:id', authenticatePIN, (req, res) => {
  const noteId = parseInt(req.params.id, 10);
  const { title, content } = req.body;

  if (!title || !content || typeof title !== 'string' || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Title dan Content wajib diisi dengan format string.',
    });
  }

  const index = notes.findIndex(n => n.id === noteId);
  if (index === -1) {
    return res.status(404).json({ success: false, error: 'Catatan tidak ditemukan.' });
  }

  notes[index] = {
    ...notes[index],
    title: title.trim().substring(0, 100),
    content: content.trim().substring(0, 500),
    updatedAt: new Date()
  };

  res.json({
    success: true,
    message: 'Catatan berhasil diperbarui.',
    data: notes[index],
  });
});

// 4. Delete Note
app.delete('/api/notes/:id', authenticatePIN, (req, res) => {
  const noteId = parseInt(req.params.id, 10);
  const index = notes.findIndex(n => n.id === noteId);

  if (index === -1) {
    return res.status(404).json({ success: false, error: 'Catatan tidak ditemukan.' });
  }

  notes.splice(index, 1);
  res.json({
    success: true,
    message: 'Catatan berhasil dihapus.',
  });
});

// 404 Handler
app.use((req, res, next) => {
  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
    return;
  }
  res.status(404).json({ success: false, error: 'Endpoint tidak ditemukan.' });
});

// Centralized Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message);
  res.status(500).json({
    success: false,
    error: 'Terjadi kesalahan internal pada server.',
  });
});

app.listen(PORT, () => {
  console.log(`Server Keamanan Informasi berjalan pada port ${PORT} [Env: ${NODE_ENV}]`);
});
