import 'dotenv/config';
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

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
const MAIL_TO = process.env.MAIL_TO || 'devehvservices@gmail.com';

if (!process.env.DATABASE_URL) {
  console.error(
    'DATABASE_URL is missing. Add your Supabase Postgres connection string.'
  );
  process.exit(1);
}

// Database connection
const sql = postgres(process.env.DATABASE_URL, {
  max: 5,
  ssl: 'require'
});

// Create database table if it doesn't exist
async function initDatabase() {
  await sql`
    CREATE TABLE IF NOT EXISTS enquiries (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT DEFAULT '',
      email TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      service TEXT DEFAULT '',
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'New'
        CHECK(status IN ('New','Contacted','Completed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
}

// Security
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      'dev-ehv-demo-change-this-secret',

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 8
    }
  })
);

// Rate limiting
app.use(
  '/api/',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// ===============================
// SERVE STATIC FILES
// ===============================

app.use(express.static(path.join(__dirname, 'public')));

// Homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Admin HTML page
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ===============================
// EMAIL CONFIGURATION
// ===============================

const smtpConfigured = Boolean(
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
);

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE) === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

// ===============================
// HELPER FUNCTIONS
// ===============================

function clean(value, max = 5000) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function requireAdmin(req, res, next) {
  if (req.session?.admin) {
    return next();
  }

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  return res.redirect('/admin.html');
}

// ===============================
// PUBLIC ENQUIRY API
// ===============================

app.post('/api/enquiries', async (req, res) => {
  try {
    const name = clean(req.body.name, 120);
    const company = clean(req.body.company, 160);
    const email = clean(req.body.email, 160);
    const phone = clean(req.body.phone, 40);
    const service = clean(req.body.service, 160);
    const message = clean(req.body.message, 5000);

    if (name.length < 2 || message.length < 5) {
      return res.status(400).json({
        error:
          'Please enter your name and a project requirement.'
      });
    }

    if (email && !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({
        error: 'Please enter a valid email address.'
      });
    }

    const [row] = await sql`
      INSERT INTO enquiries
      (
        name,
        company,
        email,
        phone,
        service,
        message
      )
      VALUES
      (
        ${name},
        ${company},
        ${email},
        ${phone},
        ${service},
        ${message}
      )
      RETURNING id
    `;

    // Send email if SMTP is configured
    if (transporter) {
      await transporter.sendMail({
        from:
          process.env.MAIL_FROM ||
          process.env.SMTP_USER,

        to: MAIL_TO,

        replyTo: email || undefined,

        subject: `New DEV EHV Website Enquiry #${row.id}`,

        text:
`Name: ${name}
Company: ${company}
Email: ${email}
Phone: ${phone}
Service: ${service}

Requirement:
${message}`
      });
    }

    res.status(201).json({
      ok: true,
      id: row.id,
      message:
        'Thank you. Your enquiry has been sent successfully.'
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error:
        'Unable to send your enquiry right now. Please try again.'
    });
  }
});

// ===============================
// ADMIN PAGE
// ===============================

app.get(
  '/admin',
  requireAdmin,
  (req, res) => {
    res.sendFile(
      path.join(__dirname, 'public', 'admin.html')
    );
  }
);

// ===============================
// ADMIN LOGIN
// ===============================

app.post(
  '/api/admin/login',

  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20
  }),

  (req, res) => {
    const username = clean(req.body.username, 80);

    const password = String(
      req.body.password || ''
    );

    if (
      username === ADMIN_USERNAME &&
      password === ADMIN_PASSWORD
    ) {
      req.session.admin = true;

      return res.json({
        ok: true
      });
    }

    res.status(401).json({
      error: 'Invalid username or password.'
    });
  }
);

// ===============================
// ADMIN LOGOUT
// ===============================

app.post(
  '/api/admin/logout',

  requireAdmin,

  (req, res) => {
    req.session.destroy(() => {
      res.json({
        ok: true
      });
    });
  }
);

// ===============================
// CHECK ADMIN LOGIN
// ===============================

app.get(
  '/api/admin/me',

  (req, res) => {
    res.json({
      authenticated:
        Boolean(req.session?.admin)
    });
  }
);

// ===============================
// GET ENQUIRIES
// ===============================

app.get(
  '/api/admin/enquiries',

  requireAdmin,

  async (req, res) => {
    try {
      const rows = await sql`
        SELECT *
        FROM enquiries

        ORDER BY
          CASE status
            WHEN 'New' THEN 0
            WHEN 'Contacted' THEN 1
            ELSE 2
          END,

          created_at DESC
      `;

      res.json(rows);

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: 'Unable to load enquiries.'
      });
    }
  }
);

// ===============================
// UPDATE ENQUIRY STATUS
// ===============================

app.patch(
  '/api/admin/enquiries/:id',

  requireAdmin,

  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const status = clean(
        req.body.status,
        20
      );

      if (
        !Number.isInteger(id) ||
        ![
          'New',
          'Contacted',
          'Completed'
        ].includes(status)
      ) {
        return res.status(400).json({
          error: 'Invalid request.'
        });
      }

      const rows = await sql`
        UPDATE enquiries
        SET status = ${status}
        WHERE id = ${id}
        RETURNING id
      `;

      if (!rows.length) {
        return res.status(404).json({
          error: 'Enquiry not found.'
        });
      }

      res.json({
        ok: true
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          'Unable to update enquiry.'
      });
    }
  }
);

// ===============================
// DELETE ENQUIRY
// ===============================

app.delete(
  '/api/admin/enquiries/:id',

  requireAdmin,

  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: 'Invalid enquiry ID.'
        });
      }

      const rows = await sql`
        DELETE FROM enquiries
        WHERE id = ${id}
        RETURNING id
      `;

      if (!rows.length) {
        return res.status(404).json({
          error: 'Enquiry not found.'
        });
      }

      res.json({
        ok: true
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          'Unable to delete enquiry.'
      });
    }
  }
);

// ===============================
// ADMIN STATISTICS
// ===============================

app.get(
  '/api/admin/stats',

  requireAdmin,

  async (req, res) => {
    try {
      const [totalRow] = await sql`
        SELECT COUNT(*)::int AS c
        FROM enquiries
      `;

      const rows = await sql`
        SELECT
          status,
          COUNT(*)::int AS c

        FROM enquiries

        GROUP BY status
      `;

      res.json({
        total: totalRow.c,

        byStatus:
          Object.fromEntries(
            rows.map(
              r => [
                r.status,
                r.c
              ]
            )
          )
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          'Unable to load statistics.'
      });
    }
  }
);

// ===============================
// START SERVER
// ===============================

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `DEV EHV Services running on port ${PORT}`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      'Database initialization failed:',
      err
    );

    process.exit(1);
  });