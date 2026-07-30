const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Kredensial Keamanan PIN Admin (Default PIN: 123456)
const ADMIN_PIN = process.env.ADMIN_PIN || '123456';

// Sanitasi URL Supabase: Bersihkan trailing slash dan redundansi /rest/v1 jika tidak sengaja tersalin
let rawSupabaseUrl = (process.env.SUPABASE_URL || '').trim();
if (rawSupabaseUrl.endsWith('/')) {
  rawSupabaseUrl = rawSupabaseUrl.slice(0, -1);
}
if (rawSupabaseUrl.endsWith('/rest/v1')) {
  rawSupabaseUrl = rawSupabaseUrl.slice(0, -8);
}
if (rawSupabaseUrl.endsWith('/')) {
  rawSupabaseUrl = rawSupabaseUrl.slice(0, -1);
}

const SUPABASE_URL = rawSupabaseUrl;
const SUPABASE_KEY = (process.env.SUPABASE_KEY || '').trim();

const isSupabaseConfigured = SUPABASE_URL && SUPABASE_KEY;

if (isSupabaseConfigured) {
  console.log(`Database Cloud terdeteksi: Menggunakan Supabase (${SUPABASE_URL})`);
} else {
  console.log('Database Cloud tidak terdeteksi: Fallback menggunakan In-Memory database.');
}

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
  max: 100,
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

// In-Memory Storage (Fallback jika Supabase belum diset)
let localNotes = [
  { id: 1, title: 'Tips Keamanan Kontainer (Local Fallback)', content: 'Selalu gunakan user non-root (USER node) di dalam Dockerfile Anda untuk menghindari privilege escalation.', createdAt: new Date() },
  { id: 2, title: 'HTTP Headers (Local Fallback)', content: 'HelmetJS membantu mengamankan Express app dengan menyetel berbagai HTTP headers secara otomatis.', createdAt: new Date() }
];
let nextLocalId = 3;

// Helper untuk fetch ke Supabase REST API
const supabaseFetch = async (endpoint, options = {}) => {
  const url = `${SUPABASE_URL}/rest/v1/${endpoint}`;
  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    ...options.headers
  };
  
  return fetch(url, { ...options, headers });
};

// Endpoint API Info (Public)
app.get('/api/info', (req, res) => {
  res.json({
    name: 'Secure Cloud Notes API',
    status: 'Active',
    environment: NODE_ENV,
    databaseType: isSupabaseConfigured ? 'Supabase PostgreSQL (Cloud Secured)' : 'In-Memory (Fallback)',
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
// OPERASI CRUD SECURE DATABASE
// ==========================================

// 1. Read All Notes
app.get('/api/notes', authenticatePIN, async (req, res) => {
  if (!isSupabaseConfigured) {
    return res.json({ success: true, count: localNotes.length, data: localNotes });
  }

  try {
    const response = await supabaseFetch('notes?select=*&order=id.asc', { method: 'GET' });
    if (!response.ok) {
      const errBody = await response.text();
      console.error(`Supabase Fetch Error [Status ${response.status}]:`, errBody);
      throw new Error(`HTTP Status ${response.status}`);
    }
    
    const data = await response.json();
    res.json({ success: true, count: data.length, data });
  } catch (error) {
    console.error('Database Error:', error.message);
    res.status(500).json({ success: false, error: 'Gagal memuat catatan dari database cloud.' });
  }
});

// 2. Create Note
app.post('/api/notes', authenticatePIN, async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content || typeof title !== 'string' || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Title dan Content wajib diisi dengan format string.',
    });
  }

  const cleanTitle = title.trim().substring(0, 100);
  const cleanContent = content.trim().substring(0, 500);

  if (!isSupabaseConfigured) {
    const newNote = { id: nextLocalId++, title: cleanTitle, content: cleanContent, createdAt: new Date() };
    localNotes.push(newNote);
    return res.status(201).json({ success: true, message: 'Catatan disimpan (In-Memory).', data: newNote });
  }

  try {
    const response = await supabaseFetch('notes', {
      method: 'POST',
      headers: { 'Prefer': 'return=representation' },
      body: JSON.stringify({ title: cleanTitle, content: cleanContent })
    });
    
    if (!response.ok) {
      const errBody = await response.text();
      console.error(`Supabase Insert Error [Status ${response.status}]:`, errBody);
      throw new Error(`HTTP Status ${response.status}`);
    }
    const data = await response.json();
    
    res.status(201).json({
      success: true,
      message: 'Catatan berhasil disimpan ke database cloud.',
      data: data[0],
    });
  } catch (error) {
    console.error('Database Error:', error.message);
    res.status(500).json({ success: false, error: 'Gagal menyimpan catatan ke database cloud.' });
  }
});

// 3. Update Note (Edit)
app.put('/api/notes/:id', authenticatePIN, async (req, res) => {
  const noteId = parseInt(req.params.id, 10);
  const { title, content } = req.body;

  if (!title || !content || typeof title !== 'string' || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Title dan Content wajib diisi dengan format string.',
    });
  }

  const cleanTitle = title.trim().substring(0, 100);
  const cleanContent = content.trim().substring(0, 500);

  if (!isSupabaseConfigured) {
    const index = localNotes.findIndex(n => n.id === noteId);
    if (index === -1) return res.status(404).json({ success: false, error: 'Catatan tidak ditemukan.' });
    localNotes[index] = { ...localNotes[index], title: cleanTitle, content: cleanContent, updatedAt: new Date() };
    return res.json({ success: true, message: 'Catatan diperbarui (In-Memory).', data: localNotes[index] });
  }

  try {
    const response = await supabaseFetch(`notes?id=eq.${noteId}`, {
      method: 'PATCH',
      headers: { 'Prefer': 'return=representation' },
      body: JSON.stringify({ title: cleanTitle, content: cleanContent })
    });
    
    if (!response.ok) {
      const errBody = await response.text();
      console.error(`Supabase Patch Error [Status ${response.status}]:`, errBody);
      throw new Error(`HTTP Status ${response.status}`);
    }
    const data = await response.json();
    
    if (data.length === 0) {
      return res.status(404).json({ success: false, error: 'Catatan tidak ditemukan.' });
    }
    
    res.json({
      success: true,
      message: 'Catatan berhasil diperbarui di database cloud.',
      data: data[0],
    });
  } catch (error) {
    console.error('Database Error:', error.message);
    res.status(500).json({ success: false, error: 'Gagal memperbarui catatan di database cloud.' });
  }
});

// 4. Delete Note
app.delete('/api/notes/:id', authenticatePIN, async (req, res) => {
  const noteId = parseInt(req.params.id, 10);

  if (!isSupabaseConfigured) {
    const index = localNotes.findIndex(n => n.id === noteId);
    if (index === -1) return res.status(404).json({ success: false, error: 'Catatan tidak ditemukan.' });
    localNotes.splice(index, 1);
    return res.json({ success: true, message: 'Catatan dihapus (In-Memory).' });
  }

  try {
    const response = await supabaseFetch(`notes?id=eq.${noteId}`, {
      method: 'DELETE',
      headers: { 'Prefer': 'return=representation' }
    });
    
    if (!response.ok) {
      const errBody = await response.text();
      console.error(`Supabase Delete Error [Status ${response.status}]:`, errBody);
      throw new Error(`HTTP Status ${response.status}`);
    }
    
    res.json({
      success: true,
      message: 'Catatan berhasil dihapus dari database cloud.',
    });
  } catch (error) {
    console.error('Database Error:', error.message);
    res.status(500).json({ success: false, error: 'Gagal menghapus catatan dari database cloud.' });
  }
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
