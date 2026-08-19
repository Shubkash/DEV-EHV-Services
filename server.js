import 'dotenv/config';
import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import postgres from 'postgres';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const MAIL_TO = process.env.MAIL_TO || 'devehvservices@gmail.com';

for (const name of ['DATABASE_URL', 'SESSION_SECRET', 'ADMIN_USERNAME']) {
  if (!process.env[name] || process.env[name].includes('replace-with') || process.env[name].includes('your-')) {
    throw new Error(`${name} must be configured before the application can start.`);
  }
}
if (!ADMIN_PASSWORD_HASH && (isProduction || !ADMIN_PASSWORD)) {
  throw new Error('ADMIN_PASSWORD_HASH must be configured in production. Create one with npm run hash-password.');
}

app.set('trust proxy', isProduction ? 1 : false);
const sql = postgres(process.env.DATABASE_URL, { max: 5, ssl: 'require' });

class PostgresSessionStore extends session.Store {
  get(sid, callback) {
    sql`SELECT sess FROM app_sessions WHERE sid = ${sid} AND expire > NOW()`
      .then(rows => {
        const stored = rows[0]?.sess;
        const sessionData = typeof stored === 'string' ? JSON.parse(stored) : stored;
        callback(null, sessionData?.cookie ? sessionData : null);
      }).catch(callback);
  }
  set(sid, sess, callback = () => {}) {
    const expire = new Date(Date.now() + (sess.cookie?.maxAge || 8 * 60 * 60 * 1000));
    sql`INSERT INTO app_sessions (sid, sess, expire) VALUES (${sid}, ${JSON.stringify(sess)}::jsonb, ${expire}) ON CONFLICT (sid) DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire`
      .then(() => callback()).catch(callback);
  }
  destroy(sid, callback = () => {}) { sql`DELETE FROM app_sessions WHERE sid = ${sid}`.then(() => callback()).catch(callback); }
  touch(sid, sess, callback = () => {}) { this.set(sid, sess, callback); }
}

async function initDatabase() {
  await sql`CREATE TABLE IF NOT EXISTS enquiries (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, company TEXT DEFAULT '', email TEXT DEFAULT '', phone TEXT DEFAULT '', service TEXT DEFAULT '', message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New','Contacted','Completed')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS enquiries_status_created_at_idx ON enquiries (status, created_at DESC)`;
  await sql`CREATE TABLE IF NOT EXISTS app_sessions (sid TEXT PRIMARY KEY, sess JSONB NOT NULL, expire TIMESTAMPTZ NOT NULL)`;
  await sql`CREATE INDEX IF NOT EXISTS app_sessions_expire_idx ON app_sessions (expire)`;
  await sql`DELETE FROM app_sessions WHERE expire < NOW()`;
}

app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], baseUri: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], imgSrc: ["'self'", 'data:'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  scriptSrc: ["'self'", "'unsafe-inline'"], connectSrc: ["'self'"], upgradeInsecureRequests: isProduction ? [] : null
}}, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(session({ store: new PostgresSessionStore(), secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction, maxAge: 8 * 60 * 60 * 1000 } }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 150, standardHeaders: true, legacyHeaders: false }));
const enquiryLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many enquiries from this connection. Please try again later.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Please try again later.' } });

function clean(value, max = 5000) { return String(value ?? '').trim().slice(0, max); }
function validId(value) { return /^\d+$/.test(value) && Number.isSafeInteger(Number(value)); }
function passwordMatches(password, encoded) {
  const [algorithm, saltHex, hashHex] = encoded.split('$');
  if (algorithm !== 'scrypt' || !saltHex || !hashHex) return false;
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64), expected = Buffer.from(hashHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function adminPasswordMatches(password) {
  if (ADMIN_PASSWORD_HASH) return passwordMatches(password, ADMIN_PASSWORD_HASH);
  if (isProduction) return false;
  const supplied = Buffer.from(password), configured = Buffer.from(ADMIN_PASSWORD || '');
  return supplied.length === configured.length && crypto.timingSafeEqual(supplied, configured);
}
function requireAdmin(req, res, next) { return req.session?.admin ? next() : res.status(401).json({ error: 'Unauthorized' }); }
function requireCsrf(req, res, next) {
  const token = req.get('x-csrf-token') || '', stored = req.session?.csrfToken || '';
  if (token && stored && token.length === stored.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(stored))) return next();
  return res.status(403).json({ error: 'Security token expired. Refresh the page and try again.' });
}
function csv(value) {
  const text = String(value ?? '');
  return `"${/^[=+\-@]/.test(text) ? "'" : ''}${text.replaceAll('"', '""')}"`;
}

app.use(express.static(path.join(__dirname, 'public'), { maxAge: isProduction ? '7d' : 0, etag: true }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/health', async (req, res) => { try { await sql`SELECT 1`; res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); } });

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter = smtpConfigured ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE) === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } }) : null;

app.post('/api/enquiries', enquiryLimiter, async (req, res) => {
  try {
    if (clean(req.body.website, 200)) return res.status(201).json({ ok: true, message: 'Thank you. Your enquiry has been sent successfully.' });
    const name = clean(req.body.name, 120), company = clean(req.body.company, 160), email = clean(req.body.email, 160), phone = clean(req.body.phone, 40), service = clean(req.body.service, 160), message = clean(req.body.message, 5000);
    if (name.length < 2 || message.length < 5) return res.status(400).json({ error: 'Please enter your name and a project requirement.' });
    if (email && !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
    const [row] = await sql`INSERT INTO enquiries (name, company, email, phone, service, message) VALUES (${name}, ${company}, ${email}, ${phone}, ${service}, ${message}) RETURNING id`;
    if (transporter) transporter.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: MAIL_TO, replyTo: email || undefined, subject: `New DEV EHV Website Enquiry #${row.id}`, text: `Name: ${name}\nCompany: ${company}\nEmail: ${email}\nPhone: ${phone}\nService: ${service}\n\nRequirement:\n${message}` }).catch(err => console.error('Enquiry email failed:', err));
    res.status(201).json({ ok: true, id: row.id, message: 'Thank you. Your enquiry has been sent successfully.' });
  } catch (err) { console.error('Enquiry submission failed:', err); res.status(500).json({ error: 'Unable to send your enquiry right now. Please try again.' }); }
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.post('/api/admin/login', loginLimiter, (req, res, next) => {
  const username = clean(req.body.username, 80), password = String(req.body.password || '');
  if (username !== ADMIN_USERNAME || !adminPasswordMatches(password)) return res.status(401).json({ error: 'Invalid username or password.' });
  req.session.regenerate(err => { if (err) return next(err); req.session.admin = true; req.session.csrfToken = crypto.randomBytes(32).toString('hex'); res.json({ ok: true }); });
});
app.post('/api/admin/logout', requireAdmin, requireCsrf, (req, res, next) => req.session.destroy(err => err ? next(err) : res.json({ ok: true })));
app.get('/api/admin/me', (req, res) => res.json({ authenticated: Boolean(req.session?.admin), csrfToken: req.session?.admin ? req.session.csrfToken : undefined }));
app.get('/api/admin/enquiries', requireAdmin, async (req, res) => {
  try { const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 250), offset = Math.max(Number(req.query.offset) || 0, 0); const rows = await sql`SELECT * FROM enquiries ORDER BY CASE status WHEN 'New' THEN 0 WHEN 'Contacted' THEN 1 ELSE 2 END, created_at DESC LIMIT ${limit} OFFSET ${offset}`; res.json(rows); } catch (err) { console.error('Loading enquiries failed:', err); res.status(500).json({ error: 'Unable to load enquiries.' }); }
});
app.get('/api/admin/enquiries.csv', requireAdmin, async (req, res) => {
  try { const rows = await sql`SELECT id, name, company, email, phone, service, message, status, created_at FROM enquiries ORDER BY created_at DESC`; const headings = ['ID', 'Name', 'Company', 'Email', 'Phone', 'Service', 'Requirement', 'Status', 'Created at']; res.attachment('dev-ehv-enquiries.csv').type('text/csv').send([headings.map(csv).join(','), ...rows.map(row => [row.id, row.name, row.company, row.email, row.phone, row.service, row.message, row.status, row.created_at.toISOString()].map(csv).join(','))].join('\n')); } catch (err) { console.error('Export failed:', err); res.status(500).json({ error: 'Unable to export enquiries.' }); }
});
app.patch('/api/admin/enquiries/:id', requireAdmin, requireCsrf, async (req, res) => {
  const id = req.params.id, status = clean(req.body.status, 20); if (!validId(id) || !['New', 'Contacted', 'Completed'].includes(status)) return res.status(400).json({ error: 'Invalid request.' });
  try { const rows = await sql`UPDATE enquiries SET status = ${status} WHERE id = ${Number(id)} RETURNING id`; if (!rows.length) return res.status(404).json({ error: 'Enquiry not found.' }); res.json({ ok: true }); } catch (err) { console.error('Update failed:', err); res.status(500).json({ error: 'Unable to update enquiry.' }); }
});
app.delete('/api/admin/enquiries/:id', requireAdmin, requireCsrf, async (req, res) => {
  const id = req.params.id; if (!validId(id)) return res.status(400).json({ error: 'Invalid enquiry ID.' });
  try { const rows = await sql`DELETE FROM enquiries WHERE id = ${Number(id)} RETURNING id`; if (!rows.length) return res.status(404).json({ error: 'Enquiry not found.' }); res.json({ ok: true }); } catch (err) { console.error('Deletion failed:', err); res.status(500).json({ error: 'Unable to delete enquiry.' }); }
});
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try { const [total] = await sql`SELECT COUNT(*)::int AS c FROM enquiries`; const rows = await sql`SELECT status, COUNT(*)::int AS c FROM enquiries GROUP BY status`; res.json({ total: total.c, byStatus: Object.fromEntries(rows.map(row => [row.status, row.c])) }); } catch (err) { console.error('Stats failed:', err); res.status(500).json({ error: 'Unable to load statistics.' }); }
});
app.use((err, req, res, next) => { console.error('Unhandled request error:', err); res.status(500).json({ error: 'Unexpected server error.' }); });
initDatabase().then(() => app.listen(PORT, () => console.log(`DEV EHV Services running on port ${PORT}`))).catch(err => { console.error('Database initialization failed:', err); process.exit(1); });
