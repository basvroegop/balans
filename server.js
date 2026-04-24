'use strict';

const express  = require('express');
const session  = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt   = require('bcryptjs');
const mysql    = require('mysql2');
const path     = require('path');

const app  = express();
const PORT = parseInt(process.env.PORT) || 8080;

const DB_CONFIG = {
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME     || 'balans',
  user:     process.env.DB_USER     || 'balans',
  password: process.env.DB_PASSWORD || 'balanspass',
  waitForConnections: true,
  connectionLimit: 10,
};

// Registered before main() so body parsing is always available
app.use(express.json({ limit: '50mb' }));

// ── Database ──────────────────────────────────────────────────────────────────

let db; // promise pool — set by initDb()

async function initDb() {
  const rawPool = mysql.createPool(DB_CONFIG);
  db = rawPool.promise();

  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      username      VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS app_state (
      user_id    INT PRIMARY KEY,
      data       LONGTEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  // Ensure default user exists
  const username = process.env.BALANS_USER     || 'admin';
  const password = process.env.BALANS_PASSWORD || 'balans';
  const [rows] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
  if (!rows.length) {
    const hash = await bcrypt.hash(password, 12);
    await db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    console.log(`Gebruiker "${username}" aangemaakt.`);
  }

  return rawPool; // raw (non-promise) pool for express-mysql-session
}

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: 'Niet ingelogd' });
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function main() {
  const rawPool = await initDb();

  // Session store in MariaDB (uses raw mysql2 pool, not promise pool)
  const sessionStore = new MySQLStore({
    clearExpired:            true,
    checkExpirationInterval: 15 * 60 * 1000, // 15 min
    expiration:              30 * 24 * 60 * 60 * 1000, // 30 days
    createDatabaseTable:     true,
    schema: { tableName: 'sessions' },
  }, rawPool);

  app.use(session({
    key:    'balans.sid',
    secret: process.env.SESSION_SECRET || 'change-this-in-production',
    store:  sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge:   30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      sameSite: 'lax',
    },
  }));

  // ── API routes ──────────────────────────────────────────────────────────────

  app.post('/api/login', async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ error: 'Vereiste velden ontbreken' });

    try {
      const [rows] = await db.execute(
        'SELECT id, password_hash FROM users WHERE username = ?', [username]
      );
      if (!rows.length)
        return res.status(401).json({ error: 'Ongeldige inloggegevens' });

      const valid = await bcrypt.compare(password, rows[0].password_hash);
      if (!valid)
        return res.status(401).json({ error: 'Ongeldige inloggegevens' });

      req.session.userId = rows[0].id;
      res.json({ ok: true });
    } catch (err) {
      console.error('Login fout:', err);
      res.status(500).json({ error: 'Serverfout' });
    }
  });

  app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
  });

  app.get('/api/me', requireAuth, (req, res) => {
    res.json({ userId: req.session.userId });
  });

  app.get('/api/state', requireAuth, async (req, res) => {
    try {
      const [rows] = await db.execute(
        'SELECT data FROM app_state WHERE user_id = ?', [req.session.userId]
      );
      if (!rows.length) return res.json(null);
      const raw = rows[0].data;
      res.json(typeof raw === 'string' ? JSON.parse(raw) : raw);
    } catch (err) {
      console.error('State ophalen mislukt:', err);
      res.status(500).json({ error: 'Serverfout' });
    }
  });

  app.put('/api/state', requireAuth, async (req, res) => {
    try {
      await db.execute(
        `INSERT INTO app_state (user_id, data) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE data = VALUES(data), updated_at = NOW()`,
        [req.session.userId, JSON.stringify(req.body)]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error('State opslaan mislukt:', err);
      res.status(500).json({ error: 'Serverfout' });
    }
  });

  // ── Frontend ────────────────────────────────────────────────────────────────

  const STATIC = ['logo.png','favicon.svg','favicon-32.png','apple-touch-icon.png','manifest.json','sw.js'];
  STATIC.forEach(f => app.get('/' + f, (req, res) => res.sendFile(path.join(__dirname, f))));

  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
  });

  app.listen(PORT, () => {
    console.log(`Balans draait op http://localhost:${PORT}`);
  });
}

main().catch(err => {
  console.error('Opstartfout:', err);
  process.exit(1);
});
