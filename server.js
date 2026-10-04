const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// Needed on Render/Vercel so req.ip is the real client IP (used for rate limiting)
app.set('trust proxy', 1);

// Security headers (this server only returns JSON, so the defaults are safe)
app.use(
  helmet({
    // The frontend lives on another domain and reads our API responses
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
);

/* =========================================================
   SERVER CONFIGURATION
   ========================================================= */

if (!process.env.JWT_SECRET) {
  console.warn(
    'JWT_SECRET is not configured. Authentication routes will reject requests.'
  );
}

/* =========================================================
   CORS
   ========================================================= */

app.use(
  cors({
    origin: [
      'https://unilnk.vercel.app',
      'http://localhost:5173',
      'http://127.0.0.1:5173'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Accept',
      'X-Requested-With'
    ],
    credentials: true
  })
);

/* =========================================================
   JSON BODY PARSER
   ========================================================= */

app.use(express.json({ limit: '100kb' }));

/* =========================================================
   RATE LIMITING
   In-memory (per server instance), which is fine for a single Render
   instance. Limits reset when the server restarts. If you ever run several
   instances, move this to Redis.

   NOTE: many students share one campus Wi-Fi IP, so per-IP limits are
   deliberately generous; per-user limits are used wherever a login exists.
   ========================================================= */

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

const RATE_LIMITS = {
  generalUser: { max: 1500, windowMs: 15 * MINUTE }, // all API calls, logged in
  generalAnon: { max: 3000, windowMs: 15 * MINUTE }, // all API calls, per IP
  loginIp: { max: 50, windowMs: 15 * MINUTE },       // login attempts per IP
  loginFail: { max: 8, windowMs: 15 * MINUTE },      // wrong passwords per email+IP
  registerIp: { max: 20, windowMs: HOUR },           // sign-ups per IP
  listingCreate: { max: 20, windowMs: HOUR },        // new listings per user
  chatSend: { max: 60, windowMs: MINUTE },           // chat messages per user
  report: { max: 10, windowMs: HOUR },               // listing reports per user
  review: { max: 10, windowMs: HOUR },               // seller reviews per user
  block: { max: 30, windowMs: HOUR }                 // block/unblock actions per user
};

const rateStore = new Map();

const rateCheck = (key, max, windowMs, { consume = true } = {}) => {
  const now = Date.now();
  const recent = (rateStore.get(key) || []).filter(
    (ts) => now - ts < windowMs
  );

  if (recent.length >= max) {
    rateStore.set(key, recent);

    return {
      limited: true,
      retryAfter: Math.max(1, Math.ceil((recent[0] + windowMs - now) / 1000))
    };
  }

  if (consume) recent.push(now);
  rateStore.set(key, recent);

  return { limited: false, remaining: max - recent.length };
};

// Records an event (e.g. a failed login) without checking the limit
const rateHit = (key) => {
  const stamps = rateStore.get(key) || [];
  stamps.push(Date.now());
  rateStore.set(key, stamps);
};

const rateReset = (key) => rateStore.delete(key);

// Used by the password reset / verification routes
const isRateLimited = (key, max, windowMs) =>
  rateCheck(key, max, windowMs).limited;

setInterval(() => {
  const cutoff = Date.now() - HOUR; // longest window is 1 hour
  for (const [key, stamps] of rateStore) {
    if (stamps.every((ts) => ts < cutoff)) rateStore.delete(key);
  }
}, 10 * MINUTE).unref();

const formatWait = (seconds) =>
  seconds < 60
    ? `${seconds} second${seconds === 1 ? '' : 's'}`
    : `${Math.ceil(seconds / 60)} minute${Math.ceil(seconds / 60) === 1 ? '' : 's'}`;

// Logged-in users are counted per account, everyone else per IP
const clientKey = (req) => {
  const header = req.headers.authorization;

  if (header && header.startsWith('Bearer ') && process.env.JWT_SECRET) {
    try {
      const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
      return `u:${decoded.id}`;
    } catch (err) {
      /* invalid token: fall through to IP */
    }
  }

  return `ip:${req.ip}`;
};

// Returns the user id from a valid token, or null (for public routes that
// behave slightly differently when the visitor is signed in)
const optionalUserId = (req) => {
  const header = req.headers.authorization;

  if (header && header.startsWith('Bearer ') && process.env.JWT_SECRET) {
    try {
      const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
      return Number(decoded.id) || null;
    } catch (err) {
      return null;
    }
  }

  return null;
};

const shortName = (fullName) => {
  const parts = String(fullName || 'Student').trim().split(/\s+/);
  return parts.length > 1
    ? `${parts[0]} ${parts[parts.length - 1][0]}.`
    : parts[0];
};

const limiter =
  ({ name, max, windowMs, key = (req) => req.ip, skip, message }) =>
  (req, res, next) => {
    if (skip && skip(req)) return next();

    const k = key(req);
    const limit = typeof max === 'function' ? max(k) : max;
    const result = rateCheck(`${name}:${k}`, limit, windowMs);

    res.set('RateLimit-Limit', String(limit));

    if (result.limited) {
      res.set('Retry-After', String(result.retryAfter));

      return res.status(429).json({
        success: false,
        error:
          message ||
          `Too many requests. Please try again in ${formatWait(result.retryAfter)}.`,
        retry_after: result.retryAfter
      });
    }

    res.set('RateLimit-Remaining', String(result.remaining));
    next();
  };

// Backstop for every API call (health check excluded)
app.use(
  '/api',
  limiter({
    name: 'api',
    key: clientKey,
    max: (k) =>
      k.startsWith('u:')
        ? RATE_LIMITS.generalUser.max
        : RATE_LIMITS.generalAnon.max,
    windowMs: RATE_LIMITS.generalUser.windowMs,
    skip: (req) => req.path === '/health'
  })
);

// Stricter limits on sensitive routes (run before the route handlers below)
app.post(
  '/api/auth/login',
  limiter({
    name: 'login-ip',
    ...RATE_LIMITS.loginIp,
    message: 'Too many sign-in attempts from this network. Please wait a few minutes and try again.'
  })
);

app.post(
  '/api/auth/register',
  limiter({
    name: 'register-ip',
    ...RATE_LIMITS.registerIp,
    message: 'Too many sign-ups from this network. Please try again later.'
  })
);

app.post(
  '/api/listings',
  limiter({
    name: 'listing-create',
    key: clientKey,
    ...RATE_LIMITS.listingCreate,
    message: 'You are posting too fast. You can create up to 20 listings per hour.'
  })
);

app.post(
  '/api/chat/send',
  limiter({
    name: 'chat-send',
    key: clientKey,
    ...RATE_LIMITS.chatSend,
    message: 'You are sending messages too fast. Please slow down.'
  })
);

app.post(
  '/api/listings/:id/report',
  limiter({
    name: 'report',
    key: clientKey,
    ...RATE_LIMITS.report,
    message: 'You have sent too many reports. Please try again later.'
  })
);

app.post(
  '/api/sellers/:id/reviews',
  limiter({
    name: 'review',
    key: clientKey,
    ...RATE_LIMITS.review,
    message: 'You are posting reviews too fast. Please try again later.'
  })
);

app.post(
  '/api/blocks/:userId',
  limiter({
    name: 'block',
    key: clientKey,
    ...RATE_LIMITS.block,
    message: 'Too many block requests. Please try again later.'
  })
);


/* =========================================================
   CLOUDINARY CONFIGURATION
   ========================================================= */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/* =========================================================
   MULTER / IMAGE UPLOAD CONFIGURATION
   ========================================================= */

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'unilnk_listings',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    // Stored images are resized on upload (max 1600px, automatic quality)
    transformation: [
      { width: 1600, height: 1600, crop: 'limit', quality: 'auto' }
    ]
  }
});

const upload = multer({
  storage,
  limits: {
    files: 5,
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = [
      'image/jpeg',
      'image/png',
      'image/webp'
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG, PNG, and WEBP images are allowed.'));
    }
  }
});

/* =========================================================
   POSTGRESQL CONNECTION
   ========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* =========================================================
   DATABASE INITIALIZATION
   ========================================================= */

const initializeDatabase = async () => {
  try {
    /* ================= USERS ================= */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        student_id VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* ================= PASSWORD RESETS ================= */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash
      ON password_resets(token_hash);
    `);

    /* ================= LISTINGS ================= */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        price NUMERIC(10,2) NOT NULL,
        quantity INTEGER DEFAULT 1,
        category VARCHAR(100),
        campus VARCHAR(255) DEFAULT 'Silverest Main Campus',
        seller_id INTEGER REFERENCES users(id),
        seller_name VARCHAR(255),
        image_url TEXT,
        course_code VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_sold BOOLEAN NOT NULL DEFAULT FALSE,
        sold_at TIMESTAMP WITHOUT TIME ZONE
      );
    `);

    /* ================= CHAT MESSAGES ================= */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        listing_id INTEGER REFERENCES listings(id),
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* ================= EXISTING COLUMN SUPPORT ================= */

    await pool.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS seller_name VARCHAR(255);
    `);

    await pool.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS is_sold BOOLEAN NOT NULL DEFAULT FALSE;
    `);

    await pool.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS sold_at TIMESTAMP WITHOUT TIME ZONE;
    `);

    /* ================= EMAIL VERIFICATION ================= */

    // Existing accounts (created before this feature) count as verified;
    // new signups default to unverified.
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE;
    `);

    await pool.query(`
      ALTER TABLE users
      ALTER COLUMN email_verified SET DEFAULT FALSE;
    `);

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_email_verifications_token_hash
      ON email_verifications(token_hash);
    `);

    /* ================= ADMIN MODERATION ================= */

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'student';
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS moderation_actions (
        id SERIAL PRIMARY KEY,
        listing_id INTEGER,
        listing_title VARCHAR(255),
        listing_price NUMERIC(10,2),
        listing_category VARCHAR(100),
        seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        seller_name VARCHAR(255),
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        admin_name VARCHAR(255),
        reason VARCHAR(100) NOT NULL,
        note TEXT,
        seller_notified BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* ================= TRUST, SAFETY, SOCIAL ================= */

    // Soft removal (admins can restore) + archiving of old sold listings
    await pool.query(`
      ALTER TABLE listings
        ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS removed_reason VARCHAR(100),
        ADD COLUMN IF NOT EXISTS removed_note TEXT,
        ADD COLUMN IF NOT EXISTS removed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
    `);

    // Account suspension
    await pool.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS ban_reason TEXT;
    `);

    // Moderation log now also records restores, bans and review removals
    await pool.query(`
      ALTER TABLE moderation_actions
        ADD COLUMN IF NOT EXISTS action VARCHAR(20) NOT NULL DEFAULT 'remove';
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS listing_reports (
        id SERIAL PRIMARY KEY,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reason VARCHAR(100) NOT NULL,
        details TEXT,
        status VARCHAR(20) NOT NULL DEFAULT 'open',
        resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        resolved_at TIMESTAMPTZ,
        resolution_note TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (listing_id, reporter_id)
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_listing_reports_status
      ON listing_reports(status, created_at);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_blocks (
        blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (blocker_id, blocked_id),
        CHECK (blocker_id <> blocked_id)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favorites (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, listing_id)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS seller_reviews (
        id SERIAL PRIMARY KEY,
        seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reviewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (seller_id, reviewer_id),
        CHECK (seller_id <> reviewer_id)
      );
    `);

    // Indexes for browsing, chat and review lookups
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_listings_browse
      ON listings (id DESC)
      WHERE is_sold = FALSE AND removed_at IS NULL;
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings (seller_id);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_chat_pair
      ON chat_messages (sender_id, receiver_id, created_at);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_chat_unread
      ON chat_messages (receiver_id, is_read);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reviews_seller ON seller_reviews (seller_id);
    `);

    /*
      Promote admins listed in the ADMIN_EMAILS environment variable
      (comma-separated). Accounts must already be registered.
    */

    const adminEmails = (process.env.ADMIN_EMAILS || '')
      .split(',')
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean);

    if (adminEmails.length > 0) {
      const promoted = await pool.query(
        `
          UPDATE users
          SET role = 'admin'
          WHERE LOWER(email) = ANY($1::text[])
            AND role <> 'admin'
        `,
        [adminEmails]
      );

      if (promoted.rowCount > 0) {
        console.log(`Promoted ${promoted.rowCount} user(s) to admin.`);
      }
    }

    console.log(
      'Database tables and sold-listing columns verified successfully.'
    );
  } catch (err) {
    console.error(
      'Database initialization error:',
      err.message
    );

    throw err;
  }
};

/* =========================================================
   AUTOMATIC SOLD-LISTING CLEANUP
   Delete sold listings after five days.
   ========================================================= */

const cleanupSoldListings = async () => {
  /*
    1) Sold listings: after 5 days the photos are deleted (saves storage) but
       the record stays, so it still counts in the seller's sold history.
    2) Removed listings: permanently deleted 30 days after a moderator
       removed them (until then an admin can still restore them).
  */
  try {
    const archived = await pool.query(`
      WITH due AS (
        SELECT id, image_url
        FROM listings
        WHERE is_sold = TRUE
          AND sold_at IS NOT NULL
          AND archived_at IS NULL
          AND sold_at <= CURRENT_TIMESTAMP - INTERVAL '5 days'
        ORDER BY id
        LIMIT 50
        FOR UPDATE
      ),
      upd AS (
        UPDATE listings l
        SET image_url = '[]', archived_at = NOW()
        FROM due
        WHERE l.id = due.id
        RETURNING l.id
      )
      SELECT due.id, due.image_url FROM due
    `);

    for (const row of archived.rows) {
      await deleteCloudinaryImages(row.image_url);
    }

    if (archived.rowCount > 0) {
      console.log(`Archived ${archived.rowCount} sold listing(s).`);
    }

    const purge = await pool.query(`
      SELECT id, image_url
      FROM listings
      WHERE removed_at IS NOT NULL
        AND removed_at <= NOW() - INTERVAL '30 days'
      ORDER BY id
      LIMIT 50
    `);

    if (purge.rows.length > 0) {
      const ids = purge.rows.map((row) => row.id);
      let client;

      try {
        client = await pool.connect();
        await client.query('BEGIN');
        await client.query(
          'UPDATE chat_messages SET listing_id = NULL WHERE listing_id = ANY($1::int[])',
          [ids]
        );
        await client.query('DELETE FROM listings WHERE id = ANY($1::int[])', [ids]);
        await client.query('COMMIT');
      } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        if (client) client.release();
      }

      for (const row of purge.rows) {
        await deleteCloudinaryImages(row.image_url);
      }

      console.log(`Permanently deleted ${ids.length} removed listing(s).`);
    }
  } catch (err) {
    console.error('Listing maintenance error:', err.message);
  }
};

/*
  Initialize the database before running cleanup.
  Repeat cleanup every hour while the backend is running.
*/

initializeDatabase()
  .then(() => {
    cleanupSoldListings();

    setInterval(
      cleanupSoldListings,
      60 * 60 * 1000
    );
  })
  .catch((err) => {
    console.error(
      'Backend database initialization failed:',
      err.message
    );
  });

/* =========================================================
   AUTH ROUTES
   ========================================================= */

/*
  PASSWORD POLICY (registration only - login must not enforce it,
  so existing users with older passwords can still sign in)
*/

const validatePassword = (password) => {
  if (typeof password !== 'string') return 'Invalid password';
  if (password.length < 8) return 'Password must be at least 8 characters long';
  // bcrypt only uses the first 72 bytes
  if (Buffer.byteLength(password, 'utf8') > 72) return 'Password must be 72 characters or fewer';
  if (!/[A-Z]/.test(password)) return 'Password must include an uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must include a lowercase letter';
  if (!/\d/.test(password)) return 'Password must include a number';
  if (!/[^A-Za-z0-9]/.test(password)) return 'Password must include a special character';
  return null;
};

/*
  REGISTER
  POST /api/auth/register
*/

app.post('/api/auth/register', async (req, res) => {
  const {
    full_name,
    email,
    password,
    student_id
  } = req.body;

  if (
    !full_name?.trim() ||
    !email?.trim() ||
    !password ||
    !student_id?.trim()
  ) {
    return res.status(400).json({
      success: false,
      error: 'Full name, email, password and student ID are required'
    });
  }

  const passwordError = validatePassword(password);

  if (passwordError) {
    return res.status(400).json({
      success: false,
      error: passwordError
    });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({
      success: false,
      error: 'Server authentication is not configured'
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await pool.query(
      `
        SELECT id, email_verified
        FROM users
        WHERE LOWER(email) = $1
      `,
      [normalizedEmail]
    );

    const passwordHash = await bcrypt.hash(password, 12);
    let user;

    if (existingUser.rows.length > 0) {
      if (existingUser.rows[0].email_verified) {
        return res.status(409).json({
          success: false,
          error: 'An account with this email already exists'
        });
      }

      /*
        An unverified account can't be used to sign in, so the real owner of
        the email is allowed to register again and take it over.
      */
      const updated = await pool.query(
        `
          UPDATE users
          SET full_name = $1, password_hash = $2, student_id = $3
          WHERE id = $4
          RETURNING id, full_name, email
        `,
        [
          full_name.trim(),
          passwordHash,
          student_id.trim(),
          existingUser.rows[0].id
        ]
      );

      user = updated.rows[0];
    } else {
      const result = await pool.query(
        `
          INSERT INTO users
            (full_name, email, password_hash, student_id)
          VALUES ($1, $2, $3, $4)
          RETURNING id, full_name, email
        `,
        [
          full_name.trim(),
          normalizedEmail,
          passwordHash,
          student_id.trim()
        ]
      );

      user = result.rows[0];
    }

    // No login token here - the user must verify their email first
    try {
      await issueVerificationEmail(user);
    } catch (mailErr) {
      console.error('Verification setup error:', mailErr);
    }

    res.status(201).json({
      success: true,
      requires_verification: true,
      message: 'Account created. Check your email to verify it.'
    });
  } catch (err) {
    console.error('Registration error:', err);

    if (err.code === '23505') {
      return res.status(409).json({
        success: false,
        error: 'An account with this email already exists'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Unable to create account'
    });
  }
});

/*
  PASSWORD RESET
  POST /api/auth/forgot-password  -> emails a single-use link (valid 30 min)
  POST /api/auth/reset-password   -> sets a new password using that link
*/

const RESET_TOKEN_TTL_MINUTES = 30;
const FRONTEND_URL = (
  process.env.FRONTEND_URL || 'https://unilnk.vercel.app'
).replace(/\/$/, '');

const hashResetToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

const escapeHtml = (str = '') =>
  String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));

// Sends through Brevo's HTTPS API (no SMTP port needed, which some hosts block)
const sendMail = async ({ to, subject, html, devLabel, devLink }) => {
  if (!process.env.BREVO_API_KEY || !process.env.MAIL_FROM) {
    if (process.env.NODE_ENV !== 'production') {
      console.log(`[DEV] ${devLabel} for ${to}: ${devLink}`);
    } else {
      console.warn(
        `${devLabel} email not sent: BREVO_API_KEY / MAIL_FROM are not set`
      );
    }
    return;
  }

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'UniLnk', email: process.env.MAIL_FROM },
      to: [{ email: to }],
      subject,
      htmlContent: html
    })
  });

  if (!response.ok) {
    throw new Error(
      `Email provider responded ${response.status}: ${await response.text()}`
    );
  }
};

const emailButton = (link, label) => `
  <p>
    <a href="${link}"
       style="background:#006633;color:#fff;padding:12px 20px;border-radius:6px;text-decoration:none;display:inline-block;">
      ${label}
    </a>
  </p>`;

const sendResetEmail = (toEmail, fullName, link) =>
  sendMail({
    to: toEmail,
    subject: 'Reset your UniLnk password',
    devLabel: 'Password reset link',
    devLink: link,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;">
        <h2>Reset your password</h2>
        <p>Hi ${escapeHtml(fullName) || 'there'},</p>
        <p>We received a request to reset your UniLnk password.
           This link works once and expires in ${RESET_TOKEN_TTL_MINUTES} minutes.</p>
        ${emailButton(link, 'Reset password')}
        <p style="color:#666;font-size:13px;">
          If you didn't ask for this, ignore this email - your password won't change.
        </p>
      </div>
    `
  });

app.post('/api/auth/forgot-password', async (req, res) => {
  const email = req.body?.email;

  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({
      success: false,
      error: 'Email is required'
    });
  }

  if (isRateLimited(`forgot:${req.ip}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests. Please try again later.'
    });
  }

  // Same reply whether or not the account exists (prevents email enumeration)
  const genericReply = {
    success: true,
    message:
      'If an account exists for that email, a reset link has been sent.'
  };

  try {
    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, full_name, email FROM users WHERE LOWER(email) = $1`,
      [normalizedEmail]
    );

    if (result.rows.length > 0) {
      const user = result.rows[0];

      const recent = await pool.query(
        `
          SELECT COUNT(*)::int AS n
          FROM password_resets
          WHERE user_id = $1
            AND created_at > NOW() - INTERVAL '15 minutes'
        `,
        [user.id]
      );

      if (recent.rows[0].n < 3) {
        const token = crypto.randomBytes(32).toString('hex');

        // Only the newest link works
        await pool.query(
          `
            UPDATE password_resets
            SET used_at = NOW()
            WHERE user_id = $1 AND used_at IS NULL
          `,
          [user.id]
        );

        await pool.query(
          `
            INSERT INTO password_resets (user_id, token_hash, expires_at)
            VALUES ($1, $2, NOW() + make_interval(mins => $3))
          `,
          [user.id, hashResetToken(token), RESET_TOKEN_TTL_MINUTES]
        );

        await pool.query(
          `DELETE FROM password_resets WHERE expires_at < NOW() - INTERVAL '1 day'`
        );

        const link = `${FRONTEND_URL}/?reset_token=${token}`;

        // Not awaited, so response time doesn't reveal whether the email exists
        sendResetEmail(user.email, user.full_name, link).catch((err) =>
          console.error('Reset email error:', err.message)
        );
      }
    }

    res.json(genericReply);
  } catch (err) {
    console.error('Forgot password error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to process request'
    });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};

  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).json({
      success: false,
      error: 'This reset link is invalid or has expired'
    });
  }

  if (isRateLimited(`reset:${req.ip}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({
      success: false,
      error: 'Too many attempts. Please try again later.'
    });
  }

  const passwordError = validatePassword(password);

  if (passwordError) {
    return res.status(400).json({
      success: false,
      error: passwordError
    });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    const found = await client.query(
      `
        SELECT id, user_id
        FROM password_resets
        WHERE token_hash = $1
          AND used_at IS NULL
          AND expires_at > NOW()
        FOR UPDATE
      `,
      [hashResetToken(token)]
    );

    if (found.rows.length === 0) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        error: 'This reset link is invalid or has expired'
      });
    }

    const { user_id: userId } = found.rows[0];
    const newHash = await bcrypt.hash(password, 12);

    await client.query(
      `
        UPDATE users
        SET password_hash = $1,
            email_verified = TRUE,
            email_verified_at = COALESCE(email_verified_at, NOW())
        WHERE id = $2
      `,
      [newHash, userId]
    );

    await client.query(
      `
        UPDATE password_resets
        SET used_at = NOW()
        WHERE user_id = $1 AND used_at IS NULL
      `,
      [userId]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Password updated. You can now sign in.'
    });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('Reset password error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to reset password'
    });
  } finally {
    if (client) client.release();
  }
});

/*
  EMAIL VERIFICATION
  POST /api/auth/verify-email
  POST /api/auth/resend-verification
*/

const VERIFY_TOKEN_TTL_HOURS = 24;

const issueVerificationEmail = async (user) => {
  const token = crypto.randomBytes(32).toString('hex');

  // Only the newest link works
  await pool.query(
    `
      UPDATE email_verifications
      SET used_at = NOW()
      WHERE user_id = $1 AND used_at IS NULL
    `,
    [user.id]
  );

  await pool.query(
    `
      INSERT INTO email_verifications (user_id, token_hash, expires_at)
      VALUES ($1, $2, NOW() + make_interval(hours => $3))
    `,
    [user.id, hashResetToken(token), VERIFY_TOKEN_TTL_HOURS]
  );

  await pool.query(
    `DELETE FROM email_verifications WHERE expires_at < NOW() - INTERVAL '7 days'`
  );

  const link = `${FRONTEND_URL}/?verify_token=${token}`;

  // Not awaited, so the response doesn't depend on the email provider
  sendMail({
    to: user.email,
    subject: 'Verify your UniLnk email',
    devLabel: 'Email verification link',
    devLink: link,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;">
        <h2>Verify your email</h2>
        <p>Hi ${escapeHtml(user.full_name) || 'there'},</p>
        <p>Welcome to UniLnk! Confirm this is your email address to activate
           your account. The link expires in ${VERIFY_TOKEN_TTL_HOURS} hours.</p>
        ${emailButton(link, 'Verify email')}
        <p style="color:#666;font-size:13px;">
          If you didn't create a UniLnk account, you can ignore this email.
        </p>
      </div>
    `
  }).catch((err) => console.error('Verification email error:', err.message));
};

app.post('/api/auth/verify-email', async (req, res) => {
  const { token } = req.body || {};

  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).json({
      success: false,
      error: 'This verification link is invalid or has expired'
    });
  }

  if (isRateLimited(`verify:${req.ip}`, 20, 15 * 60 * 1000)) {
    return res.status(429).json({
      success: false,
      error: 'Too many attempts. Please try again later.'
    });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    const found = await client.query(
      `
        SELECT id, user_id
        FROM email_verifications
        WHERE token_hash = $1
          AND used_at IS NULL
          AND expires_at > NOW()
        FOR UPDATE
      `,
      [hashResetToken(token)]
    );

    if (found.rows.length === 0) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        error:
          'This verification link is invalid or has expired. If you already verified, just sign in.'
      });
    }

    const { user_id: userId } = found.rows[0];

    await client.query(
      `
        UPDATE users
        SET email_verified = TRUE, email_verified_at = NOW()
        WHERE id = $1
      `,
      [userId]
    );

    await client.query(
      `
        UPDATE email_verifications
        SET used_at = NOW()
        WHERE user_id = $1 AND used_at IS NULL
      `,
      [userId]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Email verified. You can now sign in.'
    });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('Verify email error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to verify email'
    });
  } finally {
    if (client) client.release();
  }
});

app.post('/api/auth/resend-verification', async (req, res) => {
  const email = req.body?.email;

  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({
      success: false,
      error: 'Email is required'
    });
  }

  if (isRateLimited(`resend:${req.ip}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests. Please try again later.'
    });
  }

  // Same reply whether or not the account exists
  const genericReply = {
    success: true,
    message:
      'If that account needs verification, a new link has been sent.'
  };

  try {
    const result = await pool.query(
      `
        SELECT id, full_name, email
        FROM users
        WHERE LOWER(email) = $1 AND email_verified = FALSE
      `,
      [email.trim().toLowerCase()]
    );

    if (result.rows.length > 0) {
      const user = result.rows[0];

      const recent = await pool.query(
        `
          SELECT COUNT(*)::int AS n
          FROM email_verifications
          WHERE user_id = $1
            AND created_at > NOW() - INTERVAL '15 minutes'
        `,
        [user.id]
      );

      if (recent.rows[0].n < 3) {
        await issueVerificationEmail(user);
      }
    }

    res.json(genericReply);
  } catch (err) {
    console.error('Resend verification error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to process request'
    });
  }
});

/*
  LOGIN
  POST /api/auth/login
*/

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email?.trim() || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password are required'
    });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({
      success: false,
      error: 'Server authentication is not configured'
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();

    // Wrong-password limit per account + IP (so one person can't lock out a victim from elsewhere)
    const failKey = `login-fail:${normalizedEmail}:${req.ip}`;
    const lock = rateCheck(
      failKey,
      RATE_LIMITS.loginFail.max,
      RATE_LIMITS.loginFail.windowMs,
      { consume: false }
    );

    if (lock.limited) {
      res.set('Retry-After', String(lock.retryAfter));

      return res.status(429).json({
        success: false,
        error: `Too many failed sign-in attempts. Try again in ${formatWait(lock.retryAfter)}, or use "Forgot password?".`,
        retry_after: lock.retryAfter
      });
    }

    const result = await pool.query(
      `
        SELECT
          id,
          full_name,
          email,
          password_hash,
          student_id,
          role,
          email_verified,
          is_banned
        FROM users
        WHERE LOWER(email) = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      rateHit(failKey);

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const dbUser = result.rows[0];

    let passwordMatches = false;

    if (dbUser.password_hash?.startsWith('$2')) {
      passwordMatches = await bcrypt.compare(
        password,
        dbUser.password_hash
      );
    } else {
      /*
        Upgrade old plaintext passwords after a successful login.
      */

      passwordMatches = dbUser.password_hash === password;

      if (passwordMatches) {
        const upgradedHash = await bcrypt.hash(password, 12);

        await pool.query(
          `
            UPDATE users
            SET password_hash = $1
            WHERE id = $2
          `,
          [upgradedHash, dbUser.id]
        );

        console.log(
          `Upgraded legacy password hash for user ${dbUser.id}`
        );
      }
    }

    if (!passwordMatches) {
      rateHit(failKey);

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    rateReset(failKey);

    if (dbUser.is_banned) {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        error: SUSPENDED_MESSAGE
      });
    }

    // Checked only after the password is right, so it can't be used to probe emails
    if (!dbUser.email_verified) {
      return res.status(403).json({
        success: false,
        code: 'EMAIL_NOT_VERIFIED',
        error: 'Please verify your email before signing in.'
      });
    }

    const user = {
      id: dbUser.id,
      full_name: dbUser.full_name,
      email: dbUser.email,
      student_id: dbUser.student_id,
      role: dbUser.role
    };

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    res.json({
      success: true,
      user,
      token
    });
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to log in'
    });
  }
});

/* =========================================================
   JWT AUTHENTICATION MIDDLEWARE
   ========================================================= */

const accountCache = new Map();
const ACCOUNT_CACHE_MS = 30 * 1000;

const getAccountState = async (id) => {
  const key = Number(id);
  const cached = accountCache.get(key);

  if (cached && cached.expires > Date.now()) return cached.state;

  const result = await pool.query(
    'SELECT role, is_banned FROM users WHERE id = $1',
    [key]
  );

  const state = result.rows[0]
    ? { role: result.rows[0].role, banned: result.rows[0].is_banned }
    : null;

  accountCache.set(key, { state, expires: Date.now() + ACCOUNT_CACHE_MS });
  return state;
};

const invalidateAccount = (id) => accountCache.delete(Number(id));

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of accountCache) {
    if (entry.expires < now) accountCache.delete(key);
  }
}, 5 * MINUTE).unref();

const SUSPENDED_MESSAGE =
  'Your account has been suspended. Contact UniLnk moderators if you think this is a mistake.';

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  const token =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({
      success: false,
      error: 'Server authentication is not configured'
    });
  }

  let decoded;

  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    console.error('JWT verification error:', err.message);

    return res.status(403).json({
      success: false,
      error: 'Invalid or expired authentication token'
    });
  }

  try {
    const state = await getAccountState(decoded.id);

    if (!state) {
      return res.status(401).json({
        success: false,
        error: 'This account no longer exists'
      });
    }

    if (state.banned) {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        error: SUSPENDED_MESSAGE
      });
    }

    req.user = decoded;
    next();
  } catch (err) {
    console.error('Account check error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to verify your account'
    });
  }
};

/* =========================================================
   LISTING ROUTES
   ========================================================= */

/*
  GET ACTIVE LISTINGS
  Sold listings are hidden from marketplace browsing.
*/

const escapeLike = (text) => text.replace(/[\\%_]/g, '\\$&');

const LISTING_ORDERS = new Map([
  ['newest', ['l.id DESC', 'page.id DESC']],
  ['price_asc', ['l.price ASC, l.id DESC', 'page.price ASC, page.id DESC']],
  ['price_desc', ['l.price DESC, l.id DESC', 'page.price DESC, page.id DESC']]
]);

app.get('/api/listings', async (req, res) => {
  try {
    const { search, category, campus, sort } = req.query;

    const page = Math.max(Number.parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(
      Math.max(Number.parseInt(req.query.limit, 10) || 12, 1),
      48
    );
    const offset = (page - 1) * limit;

    const params = [];
    const where = [
      'l.is_sold = FALSE',
      'l.removed_at IS NULL',
      'COALESCE(u.is_banned, FALSE) = FALSE'
    ];

    if (category && category !== 'All') {
      params.push(String(category));
      where.push(`l.category = $${params.length}`);
    }

    if (campus && campus !== 'All') {
      params.push(String(campus));
      where.push(`l.campus = $${params.length}`);
    }

    const minPrice = Number(req.query.min_price);
    if (req.query.min_price !== undefined && req.query.min_price !== '' && Number.isFinite(minPrice)) {
      params.push(minPrice);
      where.push(`l.price >= $${params.length}`);
    }

    const maxPrice = Number(req.query.max_price);
    if (req.query.max_price !== undefined && req.query.max_price !== '' && Number.isFinite(maxPrice)) {
      params.push(maxPrice);
      where.push(`l.price <= $${params.length}`);
    }

    // Every search word must appear somewhere in the title, description, course code or category
    const terms = String(search || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 5);

    for (const term of terms) {
      params.push(`%${escapeLike(term.slice(0, 50))}%`);
      const i = params.length;
      where.push(`(
        l.title ILIKE $${i}
        OR l.description ILIKE $${i}
        OR l.course_code ILIKE $${i}
        OR l.category ILIKE $${i}
      )`);
    }

    const [innerOrder, outerOrder] =
      LISTING_ORDERS.get(sort) || LISTING_ORDERS.get('newest');

    const fromSql = `
      FROM listings l
      LEFT JOIN users u ON u.id = l.seller_id
      WHERE ${where.join(' AND ')}
    `;

    const totalResult = await pool.query(
      `SELECT COUNT(*)::int AS total ${fromSql}`,
      params
    );

    const dataResult = await pool.query(
      `
        SELECT
          page.*,
          rating.avg AS seller_rating,
          COALESCE(rating.n, 0) AS seller_review_count
        FROM (
          SELECT l.*, u.full_name AS seller_name
          ${fromSql}
          ORDER BY ${innerOrder}
          LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        ) page
        LEFT JOIN LATERAL (
          SELECT
            ROUND(AVG(r.rating)::numeric, 1)::float AS avg,
            COUNT(*)::int AS n
          FROM seller_reviews r
          WHERE r.seller_id = page.seller_id
        ) rating ON TRUE
        ORDER BY ${outerOrder}
      `,
      [...params, limit, offset]
    );

    const total = totalResult.rows[0].total;

    res.json({
      success: true,
      data: dataResult.rows,
      pagination: {
        page,
        limit,
        total,
        has_more: offset + dataResult.rows.length < total
      }
    });
  } catch (err) {
    console.error('Error fetching listings:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to fetch listings'
    });
  }
});

/*
  CREATE LISTING
*/

app.post(
  '/api/listings',
  authenticateToken,
  upload.any(),
  async (req, res) => {
    try {
      const {
        title,
        description,
        price,
        quantity,
        category,
        campus,
        course_code
      } = req.body;

      if (!title?.trim()) {
        return res.status(400).json({
          success: false,
          error: 'Title is required'
        });
      }

      if (
        price === undefined ||
        price === null ||
        price === ''
      ) {
        return res.status(400).json({
          success: false,
          error: 'Price is required'
        });
      }

      const seller_id = req.user.id;

      const userResult = await pool.query(
        `
          SELECT full_name
          FROM users
          WHERE id = $1
        `,
        [seller_id]
      );

      const seller_name =
        userResult.rows[0]?.full_name || null;

      const imageUrls =
        req.files && req.files.length > 0
          ? req.files.map((file) => file.path)
          : [];

      const imagePayload = JSON.stringify(imageUrls);

      const courseCodeValue = course_code || 'GEN001';
      const campusValue = campus || 'Silverest Main Campus';

      const parsedQuantity = Number.parseInt(quantity, 10);
      const quantityValue =
        Number.isInteger(parsedQuantity) && parsedQuantity > 0
          ? parsedQuantity
          : 1;

      const priceValue = Number(price);

      if (!Number.isFinite(priceValue) || priceValue < 0) {
        return res.status(400).json({
          success: false,
          error: 'Price must be a valid non-negative number'
        });
      }

      const result = await pool.query(
        `
          INSERT INTO listings
          (
            title,
            description,
            price,
            quantity,
            category,
            campus,
            seller_id,
            seller_name,
            image_url,
            course_code
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          RETURNING *
        `,
        [
          title.trim(),
          description || '',
          priceValue,
          quantityValue,
          category || 'Other',
          campusValue,
          seller_id,
          seller_name,
          imagePayload,
          courseCodeValue
        ]
      );

      res.json({
        success: true,
        data: result.rows[0]
      });
    } catch (err) {
      console.error('Error creating listing:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to create listing'
      });
    }
  }
);

/*
  UPDATE LISTING
  Only the owner can update an unsold listing.
*/

app.put(
  '/api/listings/:id',
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;

    const {
      price,
      quantity,
      title,
      description
    } = req.body;

    try {
      const result = await pool.query(
        `
          UPDATE listings
          SET
            price = COALESCE($1, price),
            quantity = COALESCE($2, quantity),
            title = COALESCE($3, title),
            description = COALESCE($4, description)
          WHERE
            id = $5
            AND seller_id = $6
            AND is_sold = FALSE
            AND removed_at IS NULL
          RETURNING *
        `,
        [
          price ?? null,
          quantity ?? null,
          title,
          description,
          id,
          req.user.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            'Listing not found, already sold, or you are not authorized to edit it'
        });
      }

      res.json({
        success: true,
        listing: result.rows[0]
      });
    } catch (err) {
      console.error('Error updating listing:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to update listing'
      });
    }
  }
);

/*
  MARK LISTING AS SOLD
  Only the owner can mark a listing as sold.
*/

app.put(
  '/api/listings/:id/sold',
  authenticateToken,
  async (req, res) => {
    try {
      const listingId = Number(req.params.id);

      if (!Number.isInteger(listingId) || listingId < 1) {
        return res.status(400).json({
          success: false,
          error: 'Invalid listing ID'
        });
      }

      const result = await pool.query(
        `
          UPDATE listings
          SET
            is_sold = TRUE,
            sold_at = CURRENT_TIMESTAMP
          WHERE
            id = $1
            AND seller_id = $2
            AND is_sold = FALSE
            AND removed_at IS NULL
          RETURNING id, title, is_sold, sold_at
        `,
        [listingId, req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            'Listing not found, already sold, or you do not own this listing'
        });
      }

      return res.json({
        success: true,
        message: 'Listing marked as sold',
        listing: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Mark listing as sold error:',
        err.message
      );

      return res.status(500).json({
        success: false,
        error: 'Failed to mark listing as sold'
      });
    }
  }
);

/*
  DELETE LISTING
*/

app.delete(
  '/api/listings/:id',
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;

    try {
      await pool.query(
        `
          UPDATE chat_messages
          SET listing_id = NULL
          WHERE listing_id IN (
            SELECT id FROM listings
            WHERE id = $1 AND seller_id = $2 AND removed_at IS NULL
          )
        `,
        [id, req.user.id]
      );

      const result = await pool.query(
        `
          DELETE FROM listings
          WHERE id = $1
            AND seller_id = $2
            AND removed_at IS NULL
          RETURNING *
        `,
        [id, req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            'Listing not found or you are not authorized to delete it'
        });
      }

      res.json({
        success: true,
        message: 'Listing deleted successfully'
      });
    } catch (err) {
      console.error('Error deleting listing:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to delete listing'
      });
    }
  }
);

/*
  GET USER LISTINGS
  Includes sold listings so the seller can see their status.
*/

app.get(
  '/api/users/:userId/listings',
  authenticateToken,
  async (req, res) => {
    const { userId } = req.params;

    if (Number(userId) !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not authorized to access this account'
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT *
          FROM listings
          WHERE seller_id = $1
          ORDER BY id DESC
        `,
        [userId]
      );

      res.json({
        success: true,
        listings: result.rows
      });
    } catch (err) {
      console.error('Error fetching seller listings:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch seller listings'
      });
    }
  }
);

/* =========================================================
   LIVE CHAT UPDATES (Server-Sent Events)
   The browser keeps one GET /api/chat/stream connection open and the
   server pushes new messages to it. Single-instance only (in memory).
   ========================================================= */

const chatStreams = new Map(); // userId -> Set of open responses
const MAX_STREAMS_PER_USER = 5;

const sendEvent = (res, event, payload) => {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
  } catch (err) {
    /* connection already closed */
  }
};

const pushToUser = (userId, event, payload) => {
  const streams = chatStreams.get(Number(userId));
  if (!streams) return;
  for (const res of streams) sendEvent(res, event, payload);
};

const closeUserStreams = (userId) => {
  const streams = chatStreams.get(Number(userId));
  if (!streams) return;
  for (const res of [...streams]) {
    try {
      res.end();
    } catch (err) {
      /* ignore */
    }
  }
  chatStreams.delete(Number(userId));
};

app.get('/api/chat/stream', authenticateToken, (req, res) => {
  const userId = Number(req.user.id);

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();
  res.write('retry: 5000\n\n');
  sendEvent(res, 'ready', { ok: true });

  let streams = chatStreams.get(userId);
  if (!streams) {
    streams = new Set();
    chatStreams.set(userId, streams);
  }

  // Keep the newest connections only
  while (streams.size >= MAX_STREAMS_PER_USER) {
    const oldest = streams.values().next().value;
    streams.delete(oldest);
    try {
      oldest.end();
    } catch (err) {
      /* ignore */
    }
  }

  streams.add(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (err) {
      /* ignore */
    }
  }, 25 * 1000);

  req.on('close', () => {
    clearInterval(heartbeat);
    streams.delete(res);
    if (streams.size === 0 && chatStreams.get(userId) === streams) {
      chatStreams.delete(userId);
    }
  });
});

/* =========================================================
   CHAT ROUTES
   ========================================================= */

/*
  GET CONVERSATIONS
*/

app.get(
  '/api/chat/conversations/:userId',
  authenticateToken,
  async (req, res) => {
    const { userId } = req.params;

    if (Number(userId) !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not authorized to access this account'
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT
            u.id AS user_id,
            u.full_name AS user_name,
            u.email,
            u.student_id,

            (
              SELECT message
              FROM chat_messages
              WHERE
                (sender_id = $1 AND receiver_id = u.id)
                OR
                (sender_id = u.id AND receiver_id = $1)
              ORDER BY created_at DESC
              LIMIT 1
            ) AS last_message,

            (
              SELECT created_at
              FROM chat_messages
              WHERE
                (sender_id = $1 AND receiver_id = u.id)
                OR
                (sender_id = u.id AND receiver_id = $1)
              ORDER BY created_at DESC
              LIMIT 1
            ) AS last_message_time,

            (
              SELECT COUNT(*)
              FROM chat_messages
              WHERE
                receiver_id = $1
                AND sender_id = u.id
                AND is_read = FALSE
                AND NOT EXISTS (
                  SELECT 1 FROM user_blocks b
                  WHERE b.blocker_id = $1 AND b.blocked_id = u.id
                )
            ) AS unread_count,

            (
              SELECT l.title
              FROM chat_messages cm
              JOIN listings l ON cm.listing_id = l.id
              WHERE
                (cm.sender_id = $1 AND cm.receiver_id = u.id)
                OR
                (cm.sender_id = u.id AND cm.receiver_id = $1)
              ORDER BY cm.created_at DESC
              LIMIT 1
            ) AS listing_title,
            EXISTS (
              SELECT 1 FROM user_blocks b
              WHERE b.blocker_id = $1 AND b.blocked_id = u.id
            ) AS blocked_by_me,
            EXISTS (
              SELECT 1 FROM user_blocks b
              WHERE b.blocker_id = u.id AND b.blocked_id = $1
            ) AS blocked_me
          FROM users u
          WHERE u.id IN (
            SELECT DISTINCT
              CASE
                WHEN sender_id = $1 THEN receiver_id
                ELSE sender_id
              END AS other_user
            FROM chat_messages
            WHERE sender_id = $1 OR receiver_id = $1
          )
          AND u.id != $1
          ORDER BY last_message_time DESC NULLS LAST
        `,
        [userId]
      );

      res.json({
        success: true,
        conversations: result.rows
      });
    } catch (err) {
      console.error('Error fetching conversations:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch conversations'
      });
    }
  }
);

/*
  TOTAL UNREAD
*/

app.get(
  '/api/chat/unread/total/:userId',
  authenticateToken,
  async (req, res) => {
    const { userId } = req.params;

    if (Number(userId) !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not authorized to access this account'
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT COUNT(*) AS total_unread
          FROM chat_messages
          WHERE receiver_id = $1
            AND is_read = FALSE
            AND NOT EXISTS (
              SELECT 1 FROM user_blocks b
              WHERE b.blocker_id = $1
                AND b.blocked_id = chat_messages.sender_id
            )
        `,
        [userId]
      );

      res.json({
        success: true,
        total_unread: Number.parseInt(
          result.rows[0].total_unread,
          10
        )
      });
    } catch (err) {
      console.error('Error getting unread count:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to get unread count'
      });
    }
  }
);

/*
  MARK MESSAGES AS READ
*/

app.put(
  '/api/chat/mark-read/:userId/:otherUserId',
  authenticateToken,
  async (req, res) => {
    const { userId, otherUserId } = req.params;

    if (Number(userId) !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not authorized to access this account'
      });
    }

    try {
      await pool.query(
        `
          UPDATE chat_messages
          SET is_read = TRUE
          WHERE
            receiver_id = $1
            AND sender_id = $2
            AND is_read = FALSE
        `,
        [userId, otherUserId]
      );

      res.json({
        success: true
      });
    } catch (err) {
      console.error('Error marking messages as read:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to mark messages as read'
      });
    }
  }
);

/*
  GET CHAT MESSAGES
  Returns the NEWEST messages first-page (oldest of that page first).
  Use offset to load older pages. has_more tells the app whether older
  messages exist.
*/

app.get(
  '/api/chat/messages/:userId/:otherUserId',
  authenticateToken,
  async (req, res) => {
    const { userId, otherUserId } = req.params;

    if (Number(userId) !== Number(req.user.id)) {
      return res.status(403).json({
        success: false,
        error: 'You are not authorized to access this account'
      });
    }

    const requestedLimit = Number(req.query.limit ?? 50);
    const requestedOffset = Number(req.query.offset ?? 0);

    if (
      !Number.isInteger(requestedLimit) ||
      requestedLimit < 1 ||
      !Number.isInteger(requestedOffset) ||
      requestedOffset < 0
    ) {
      return res.status(400).json({
        success: false,
        error: 'Invalid pagination parameters'
      });
    }

    const limit = Math.min(requestedLimit, 100);
    const offset = requestedOffset;

    try {
      const [result, blockResult] = await Promise.all([
        pool.query(
          `
            SELECT *
            FROM (
              SELECT
                cm.*,
                u1.full_name AS sender_name,
                u2.full_name AS receiver_name,
                l.title AS listing_title
              FROM chat_messages cm
              LEFT JOIN users u1 ON cm.sender_id = u1.id
              LEFT JOIN users u2 ON cm.receiver_id = u2.id
              LEFT JOIN listings l ON cm.listing_id = l.id
              WHERE
                (cm.sender_id = $1 AND cm.receiver_id = $2)
                OR
                (cm.sender_id = $2 AND cm.receiver_id = $1)
              ORDER BY cm.created_at DESC, cm.id DESC
              LIMIT $3
              OFFSET $4
            ) latest
            ORDER BY latest.created_at ASC, latest.id ASC
          `,
          [userId, otherUserId, limit + 1, offset]
        ),
        pool.query(
          `
            SELECT
              EXISTS (
                SELECT 1 FROM user_blocks
                WHERE blocker_id = $1 AND blocked_id = $2
              ) AS blocked_by_me,
              EXISTS (
                SELECT 1 FROM user_blocks
                WHERE blocker_id = $2 AND blocked_id = $1
              ) AS blocked_me
          `,
          [userId, otherUserId]
        )
      ]);

      // One extra (oldest) row was fetched only to learn whether more exist
      const hasMore = result.rows.length > limit;
      const messages = hasMore ? result.rows.slice(1) : result.rows;

      res.json({
        success: true,
        messages,
        has_more: hasMore,
        blocked_by_me: blockResult.rows[0].blocked_by_me,
        blocked_me: blockResult.rows[0].blocked_me
      });
    } catch (err) {
      console.error('Error fetching chat messages:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch chat messages'
      });
    }
  }
);

/*
  SEND CHAT MESSAGE
*/

app.post(
  '/api/chat/send',
  authenticateToken,
  async (req, res) => {
    const sender_id = req.user.id;

    const {
      receiver_id,
      listing_id,
      message
    } = req.body;

    if (
      !receiver_id ||
      !message ||
      typeof message !== 'string' ||
      !message.trim()
    ) {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid required fields'
      });
    }

    if (message.trim().length > 2000) {
      return res.status(400).json({
        success: false,
        error: 'Messages can be at most 2000 characters long'
      });
    }

    if (Number(receiver_id) === Number(sender_id)) {
      return res.status(400).json({
        success: false,
        error: 'You cannot send a message to yourself'
      });
    }

    try {
      const recipientResult = await pool.query(
        'SELECT id, is_banned FROM users WHERE id = $1',
        [receiver_id]
      );

      if (
        recipientResult.rows.length === 0 ||
        recipientResult.rows[0].is_banned
      ) {
        return res.status(404).json({
          success: false,
          error: 'Recipient not found'
        });
      }

      // Either person blocking the other ends the conversation
      const blockResult = await pool.query(
        `
          SELECT 1
          FROM user_blocks
          WHERE (blocker_id = $1 AND blocked_id = $2)
             OR (blocker_id = $2 AND blocked_id = $1)
          LIMIT 1
        `,
        [sender_id, receiver_id]
      );

      if (blockResult.rows.length > 0) {
        return res.status(403).json({
          success: false,
          code: 'BLOCKED',
          error: "You can't send messages to this user."
        });
      }

      /*
        If a listing ID is supplied, verify that it exists.
        Sold listings can still be discussed through existing chats.
      */
      if (listing_id) {
        const listingResult = await pool.query(
          'SELECT id FROM listings WHERE id = $1 AND removed_at IS NULL',
          [listing_id]
        );

        if (listingResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            error: 'Listing not found'
          });
        }
      }

      const result = await pool.query(
        `
          INSERT INTO chat_messages
            (sender_id, receiver_id, listing_id, message)
          VALUES ($1, $2, $3, $4)
          RETURNING *
        `,
        [
          sender_id,
          receiver_id,
          listing_id || null,
          message.trim()
        ]
      );

      const senderResult = await pool.query(
        'SELECT full_name FROM users WHERE id = $1',
        [sender_id]
      );

      const payload = {
        ...result.rows[0],
        sender_name: senderResult.rows[0]?.full_name || 'Student'
      };

      // Live delivery (the sender's other tabs get it too)
      pushToUser(receiver_id, 'message', payload);
      pushToUser(sender_id, 'message', payload);

      res.json({
        success: true,
        message: payload
      });
    } catch (err) {
      console.error('Error sending message:', err);

      res.status(500).json({
        success: false,
        error: 'Failed to send message'
      });
    }
  }
);

/* =========================================================
   FAVOURITES (WISHLIST)
   ========================================================= */

app.get('/api/favorites/ids', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT listing_id FROM favorites WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      success: true,
      ids: result.rows.map((row) => row.listing_id)
    });
  } catch (err) {
    console.error('Error fetching favourite ids:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to fetch favourites'
    });
  }
});

app.get('/api/favorites', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT
          l.*,
          u.full_name AS seller_name,
          f.created_at AS favorited_at
        FROM favorites f
        JOIN listings l ON l.id = f.listing_id
        LEFT JOIN users u ON u.id = l.seller_id
        WHERE f.user_id = $1
          AND l.removed_at IS NULL
          AND COALESCE(u.is_banned, FALSE) = FALSE
        ORDER BY f.created_at DESC
        LIMIT 200
      `,
      [req.user.id]
    );

    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching favourites:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to fetch favourites'
    });
  }
});

app.post('/api/favorites/:listingId', authenticateToken, async (req, res) => {
  const listingId = Number(req.params.listingId);

  if (!Number.isInteger(listingId) || listingId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid listing ID'
    });
  }

  try {
    const listing = await pool.query(
      `
        SELECT l.id
        FROM listings l
        LEFT JOIN users u ON u.id = l.seller_id
        WHERE l.id = $1
          AND l.removed_at IS NULL
          AND COALESCE(u.is_banned, FALSE) = FALSE
      `,
      [listingId]
    );

    if (listing.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Listing not found'
      });
    }

    const count = await pool.query(
      'SELECT COUNT(*)::int AS n FROM favorites WHERE user_id = $1',
      [req.user.id]
    );

    if (count.rows[0].n >= 200) {
      return res.status(400).json({
        success: false,
        error: 'You can save up to 200 listings. Remove some first.'
      });
    }

    await pool.query(
      `
        INSERT INTO favorites (user_id, listing_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
      `,
      [req.user.id, listingId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error saving favourite:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to save listing'
    });
  }
});

app.delete('/api/favorites/:listingId', authenticateToken, async (req, res) => {
  const listingId = Number(req.params.listingId);

  if (!Number.isInteger(listingId) || listingId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid listing ID'
    });
  }

  try {
    await pool.query(
      'DELETE FROM favorites WHERE user_id = $1 AND listing_id = $2',
      [req.user.id, listingId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error removing favourite:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to remove saved listing'
    });
  }
});

/* =========================================================
   REPORT A LISTING
   ========================================================= */

const REPORT_REASONS = [
  'Scam or fraud',
  'Prohibited item',
  'Inappropriate content',
  'Fake or misleading',
  'Spam or duplicate',
  'Wrong category',
  'Other'
];

app.get('/api/report-reasons', (req, res) => {
  res.json({ success: true, reasons: REPORT_REASONS });
});

app.post('/api/listings/:id/report', authenticateToken, async (req, res) => {
  const listingId = Number(req.params.id);
  const { reason } = req.body || {};
  const details = String(req.body?.details || '').trim().slice(0, 500);

  if (!Number.isInteger(listingId) || listingId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid listing ID'
    });
  }

  if (!REPORT_REASONS.includes(reason)) {
    return res.status(400).json({
      success: false,
      error: 'Please choose a reason for your report'
    });
  }

  try {
    const listing = await pool.query(
      'SELECT id, seller_id FROM listings WHERE id = $1 AND removed_at IS NULL',
      [listingId]
    );

    if (listing.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Listing not found'
      });
    }

    if (Number(listing.rows[0].seller_id) === Number(req.user.id)) {
      return res.status(400).json({
        success: false,
        error: 'You cannot report your own listing'
      });
    }

    const inserted = await pool.query(
      `
        INSERT INTO listing_reports (listing_id, reporter_id, reason, details)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (listing_id, reporter_id) DO NOTHING
        RETURNING id
      `,
      [listingId, req.user.id, reason, details || null]
    );

    if (inserted.rows.length === 0) {
      return res.status(409).json({
        success: false,
        error: 'You have already reported this listing'
      });
    }

    res.json({
      success: true,
      message: 'Thanks. A moderator will review this listing.'
    });
  } catch (err) {
    console.error('Error reporting listing:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to submit report'
    });
  }
});

/* =========================================================
   BLOCK USERS
   ========================================================= */

app.get('/api/blocks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT u.id, u.full_name
        FROM user_blocks b
        JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = $1
        ORDER BY b.created_at DESC
      `,
      [req.user.id]
    );

    res.json({ success: true, blocked: result.rows });
  } catch (err) {
    console.error('Error fetching blocks:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to fetch blocked users'
    });
  }
});

app.post('/api/blocks/:userId', authenticateToken, async (req, res) => {
  const targetId = Number(req.params.userId);

  if (!Number.isInteger(targetId) || targetId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid user ID'
    });
  }

  if (targetId === Number(req.user.id)) {
    return res.status(400).json({
      success: false,
      error: 'You cannot block yourself'
    });
  }

  try {
    const target = await pool.query('SELECT id FROM users WHERE id = $1', [
      targetId
    ]);

    if (target.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await pool.query(
      `
        INSERT INTO user_blocks (blocker_id, blocked_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
      `,
      [req.user.id, targetId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error blocking user:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to block user'
    });
  }
});

app.delete('/api/blocks/:userId', authenticateToken, async (req, res) => {
  const targetId = Number(req.params.userId);

  if (!Number.isInteger(targetId) || targetId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid user ID'
    });
  }

  try {
    await pool.query(
      'DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [req.user.id, targetId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error unblocking user:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to unblock user'
    });
  }
});

/* =========================================================
   SELLER PROFILES, SOLD HISTORY AND REVIEWS
   ========================================================= */

// A review needs a real two-way conversation between the two students
const hasConversation = async (userA, userB) => {
  const result = await pool.query(
    `
      SELECT
        EXISTS (
          SELECT 1 FROM chat_messages WHERE sender_id = $1 AND receiver_id = $2
        )
        AND EXISTS (
          SELECT 1 FROM chat_messages WHERE sender_id = $2 AND receiver_id = $1
        ) AS ok
    `,
    [userA, userB]
  );

  return result.rows[0].ok;
};

app.get('/api/sellers/:id', async (req, res) => {
  const sellerId = Number(req.params.id);

  if (!Number.isInteger(sellerId) || sellerId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid seller ID'
    });
  }

  const viewerId = optionalUserId(req);

  try {
    const userResult = await pool.query(
      'SELECT id, full_name, created_at, is_banned FROM users WHERE id = $1',
      [sellerId]
    );

    if (userResult.rows.length === 0 || userResult.rows[0].is_banned) {
      return res.status(404).json({
        success: false,
        error: 'Seller not found'
      });
    }

    const [stats, listings, sold, reviews] = await Promise.all([
      pool.query(
        `
          SELECT
            (SELECT ROUND(AVG(rating)::numeric, 1)::float
               FROM seller_reviews WHERE seller_id = $1) AS rating,
            (SELECT COUNT(*)::int
               FROM seller_reviews WHERE seller_id = $1) AS review_count,
            (SELECT COUNT(*)::int FROM listings
               WHERE seller_id = $1 AND is_sold = FALSE
                 AND removed_at IS NULL) AS active_count,
            (SELECT COUNT(*)::int FROM listings
               WHERE seller_id = $1 AND is_sold = TRUE
                 AND removed_at IS NULL) AS sold_count
        `,
        [sellerId]
      ),
      pool.query(
        `
          SELECT id, title, price, quantity, category, campus, image_url, created_at
          FROM listings
          WHERE seller_id = $1 AND is_sold = FALSE AND removed_at IS NULL
          ORDER BY id DESC
          LIMIT 24
        `,
        [sellerId]
      ),
      pool.query(
        `
          SELECT id, title, price, category, sold_at
          FROM listings
          WHERE seller_id = $1 AND is_sold = TRUE AND removed_at IS NULL
          ORDER BY sold_at DESC NULLS LAST, id DESC
          LIMIT 20
        `,
        [sellerId]
      ),
      pool.query(
        `
          SELECT
            r.id, r.rating, r.comment, r.created_at, r.reviewer_id,
            u.full_name AS reviewer_name
          FROM seller_reviews r
          LEFT JOIN users u ON u.id = r.reviewer_id
          WHERE r.seller_id = $1
          ORDER BY r.created_at DESC
          LIMIT 30
        `,
        [sellerId]
      )
    ]);

    let canReview = false;
    let reviewHint = null;
    let myReview = null;

    if (viewerId && viewerId !== sellerId) {
      canReview = await hasConversation(viewerId, sellerId);

      if (!canReview) {
        reviewHint =
          'You can review a seller after the two of you have exchanged messages.';
      }

      const mine = await pool.query(
        'SELECT rating, comment FROM seller_reviews WHERE seller_id = $1 AND reviewer_id = $2',
        [sellerId, viewerId]
      );

      myReview = mine.rows[0] || null;
    }

    const seller = userResult.rows[0];

    res.json({
      success: true,
      seller: {
        id: seller.id,
        full_name: seller.full_name,
        joined: seller.created_at
      },
      stats: stats.rows[0],
      listings: listings.rows,
      sold: sold.rows,
      reviews: reviews.rows.map((row) => ({
        id: row.id,
        rating: row.rating,
        comment: row.comment,
        created_at: row.created_at,
        reviewer_name: shortName(row.reviewer_name),
        is_mine: viewerId !== null && Number(row.reviewer_id) === viewerId
      })),
      viewer: {
        is_self: viewerId === sellerId,
        can_review: canReview,
        review_hint: reviewHint,
        my_review: myReview
      }
    });
  } catch (err) {
    console.error('Error fetching seller profile:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to load seller profile'
    });
  }
});

app.post('/api/sellers/:id/reviews', authenticateToken, async (req, res) => {
  const sellerId = Number(req.params.id);
  const rating = Number(req.body?.rating);
  const comment = String(req.body?.comment || '').trim().slice(0, 500);

  if (!Number.isInteger(sellerId) || sellerId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid seller ID'
    });
  }

  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({
      success: false,
      error: 'Please choose a rating from 1 to 5 stars'
    });
  }

  if (sellerId === Number(req.user.id)) {
    return res.status(400).json({
      success: false,
      error: 'You cannot review yourself'
    });
  }

  try {
    const seller = await pool.query(
      'SELECT id, is_banned FROM users WHERE id = $1',
      [sellerId]
    );

    if (seller.rows.length === 0 || seller.rows[0].is_banned) {
      return res.status(404).json({
        success: false,
        error: 'Seller not found'
      });
    }

    if (!(await hasConversation(req.user.id, sellerId))) {
      return res.status(403).json({
        success: false,
        error:
          'You can review a seller after the two of you have exchanged messages.'
      });
    }

    const result = await pool.query(
      `
        INSERT INTO seller_reviews (seller_id, reviewer_id, rating, comment)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (seller_id, reviewer_id)
        DO UPDATE SET
          rating = EXCLUDED.rating,
          comment = EXCLUDED.comment,
          updated_at = NOW()
        RETURNING id, rating, comment
      `,
      [sellerId, req.user.id, rating, comment || null]
    );

    res.json({ success: true, review: result.rows[0] });
  } catch (err) {
    console.error('Error saving review:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to save review'
    });
  }
});

app.delete('/api/sellers/:id/reviews', authenticateToken, async (req, res) => {
  const sellerId = Number(req.params.id);

  if (!Number.isInteger(sellerId) || sellerId < 1) {
    return res.status(400).json({
      success: false,
      error: 'Invalid seller ID'
    });
  }

  try {
    await pool.query(
      'DELETE FROM seller_reviews WHERE seller_id = $1 AND reviewer_id = $2',
      [sellerId, req.user.id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting review:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to delete review'
    });
  }
});

/* =========================================================
   SESSION
   ========================================================= */

/*
  CURRENT USER
  Lets the frontend refresh the role after a promotion or demotion.
*/

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT id, full_name, email, student_id, role
        FROM users
        WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Account not found'
      });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Error fetching current user:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to fetch account'
    });
  }
});

/* =========================================================
   ADMIN MODERATION
   ========================================================= */

/*
  Listings whose title or description contain one of these phrases
  are surfaced in the admin "Flagged" queue. Flags are only hints for
  a human to review; nothing is ever removed automatically.
  Edit this list to match your campus rules.
*/

const FLAG_KEYWORDS = [
  // Weapons
  'gun', 'guns', 'pistol', 'rifle', 'revolver', 'shotgun', 'firearm',
  'ammo', 'ammunition', 'grenade', 'explosive', 'explosives',
  // Drugs and alcohol
  'weed', 'marijuana', 'cannabis', 'mbanje', 'cocaine', 'heroin',
  'meth', 'ecstasy', 'lsd', 'alcohol', 'vodka', 'whisky', 'whiskey',
  // Academic dishonesty
  'leaked exam', 'exam leak', 'exam answers', 'leaked paper',
  'write your assignment', 'do your assignment', 'assignment writing',
  'essay writing', 'ghostwriting',
  // Fakes and stolen goods
  'fake id', 'fake certificate', 'fake degree', 'counterfeit',
  'forged', 'forgery', 'stolen',
  // Adult content
  'porn', 'nude', 'nudes', 'escort'
];

const escapeRegex = (text) =>
  text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s+');

const SORTED_FLAG_KEYWORDS = [...FLAG_KEYWORDS].sort(
  (a, b) => b.length - a.length
);

// PostgreSQL pattern (\m and \M mark word boundaries)
const FLAG_SQL_PATTERN =
  '\\m(?:' + SORTED_FLAG_KEYWORDS.map(escapeRegex).join('|') + ')\\M';

// JavaScript pattern used to report which terms matched
const FLAG_JS_PATTERN = new RegExp(
  '\\b(?:' + SORTED_FLAG_KEYWORDS.map(escapeRegex).join('|') + ')\\b',
  'gi'
);

const findFlaggedTerms = (title, description) => {
  const text = `${title || ''} ${description || ''}`;
  const matches = text.match(FLAG_JS_PATTERN) || [];

  return [
    ...new Set(matches.map((m) => m.toLowerCase().replace(/\s+/g, ' ')))
  ];
};

const REMOVAL_REASONS = [
  'Weapons',
  'Drugs or alcohol',
  'Academic dishonesty',
  'Fake or counterfeit items',
  'Stolen goods',
  'Adult or inappropriate content',
  'Scam or misleading',
  'Spam or duplicate',
  'Other prohibited item'
];

const FLAGGED_SQL = `
  (
    NOT l.is_sold
    AND l.removed_at IS NULL
    AND (COALESCE(l.title, '') || ' ' || COALESCE(l.description, ''))
        ~* $1
  )
`;

const requireAdmin = async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, full_name, role FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Administrator access required'
      });
    }

    req.admin = result.rows[0];

    next();
  } catch (err) {
    console.error('Admin check error:', err);

    res.status(500).json({
      success: false,
      error: 'Unable to verify administrator access'
    });
  }
};

const parseImageUrls = (imageUrl) => {
  if (!imageUrl) return [];

  try {
    if (typeof imageUrl === 'string' && imageUrl.startsWith('[')) {
      const parsed = JSON.parse(imageUrl);
      return Array.isArray(parsed) ? parsed : [];
    }
  } catch {
    return [];
  }

  return [imageUrl];
};

const deleteCloudinaryImages = async (imageUrl) => {
  const urls = parseImageUrls(imageUrl);

  for (const url of urls) {
    const match = String(url).match(/\/upload\/(?:v\d+\/)?(.+)\.[a-z0-9]+$/i);
    const publicId = match ? decodeURIComponent(match[1]) : null;

    if (!publicId || !publicId.startsWith('unilnk_listings/')) continue;

    try {
      await cloudinary.uploader.destroy(publicId);
    } catch (err) {
      console.error('Cloudinary cleanup failed:', err.message);
    }
  }
};

const parsePagination = (query, defaultLimit, maxLimit) => {
  const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
  const limit = Math.min(
    Math.max(Number.parseInt(query.limit, 10) || defaultLimit, 1),
    maxLimit
  );

  return { page, limit, offset: (page - 1) * limit };
};

/*
  MODERATION OVERVIEW
*/

app.get(
  '/api/admin/stats',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          SELECT
            (SELECT COUNT(*)::int FROM users) AS total_users,
            (SELECT COUNT(*)::int FROM users WHERE is_banned) AS banned_users,
            (SELECT COUNT(*)::int FROM listings
               WHERE is_sold = FALSE AND removed_at IS NULL)
              AS active_listings,
            (SELECT COUNT(*)::int FROM listings WHERE is_sold = TRUE)
              AS sold_listings,
            (SELECT COUNT(*)::int FROM listings WHERE removed_at IS NOT NULL)
              AS removed_listings,
            (SELECT COUNT(*)::int FROM listing_reports WHERE status = 'open')
              AS open_reports,
            (
              SELECT COUNT(*)::int
              FROM listings l
              WHERE ${FLAGGED_SQL}
            ) AS flagged_listings,
            (
              SELECT COUNT(*)::int
              FROM moderation_actions
              WHERE action = 'remove'
                AND created_at >= NOW() - INTERVAL '7 days'
            ) AS removed_7d,
            (SELECT COUNT(*)::int FROM moderation_actions WHERE action = 'remove')
              AS removed_total
        `,
        [FLAG_SQL_PATTERN]
      );

      res.json({ success: true, stats: result.rows[0] });
    } catch (err) {
      console.error('Error fetching admin stats:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch moderation overview'
      });
    }
  }
);

/*
  LIST LISTINGS FOR MODERATION
  Query: search, status (all | active | sold | flagged),
         category, campus, page, limit
*/

app.get(
  '/api/admin/listings',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { search, status, category, campus } = req.query;
      const { page, limit, offset } = parsePagination(req.query, 12, 50);

      const params = [FLAG_SQL_PATTERN];
      const conditions = [];

      if (status === 'active') {
        conditions.push('l.is_sold = FALSE AND l.removed_at IS NULL');
      } else if (status === 'sold') {
        conditions.push('l.is_sold = TRUE');
      } else if (status === 'flagged') {
        conditions.push(FLAGGED_SQL);
      } else if (status === 'removed') {
        conditions.push('l.removed_at IS NOT NULL');
      } else if (status === 'reported') {
        conditions.push(`EXISTS (
          SELECT 1 FROM listing_reports rp
          WHERE rp.listing_id = l.id AND rp.status = 'open'
        )`);
      }

      if (category && category !== 'All') {
        params.push(category);
        conditions.push(`l.category = $${params.length}`);
      }

      if (campus && campus !== 'All') {
        params.push(campus);
        conditions.push(`l.campus = $${params.length}`);
      }

      if (search && String(search).trim()) {
        params.push(`%${String(search).trim()}%`);
        const i = params.length;

        conditions.push(`(
          l.title ILIKE $${i}
          OR l.description ILIKE $${i}
          OR u.full_name ILIKE $${i}
          OR u.email ILIKE $${i}
          OR u.student_id ILIKE $${i}
        )`);
      }

      const where =
        conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const baseQuery = `
        SELECT
          l.id,
          l.title,
          l.description,
          l.price,
          l.quantity,
          l.category,
          l.campus,
          l.image_url,
          l.created_at,
          l.is_sold,
          l.sold_at,
          l.seller_id,
          l.removed_at,
          l.removed_reason,
          l.removed_note,
          COALESCE(u.full_name, l.seller_name) AS seller_name,
          u.email AS seller_email,
          u.student_id AS seller_student_id,
          (
            SELECT COUNT(*)::int
            FROM moderation_actions m
            WHERE m.seller_id = l.seller_id AND m.action = 'remove'
          ) AS seller_prior_removals,
          ${FLAGGED_SQL} AS is_flagged,
          (
            SELECT COUNT(*)::int
            FROM listing_reports rp
            WHERE rp.listing_id = l.id AND rp.status = 'open'
          ) AS open_reports
        FROM listings l
        LEFT JOIN users u ON u.id = l.seller_id
        ${where}
      `;

      const totalResult = await pool.query(
        `SELECT COUNT(*)::int AS total FROM (${baseQuery}) counted`,
        params
      );

      const listingsResult = await pool.query(
        `
          ${baseQuery}
          ORDER BY ${
            status === 'removed'
              ? 'removed_at DESC'
              : 'open_reports DESC, is_flagged DESC, l.id DESC'
          }
          LIMIT $${params.length + 1}
          OFFSET $${params.length + 2}
        `,
        [...params, limit, offset]
      );

      const listings = listingsResult.rows.map((row) => ({
        ...row,
        flagged_terms: row.is_flagged
          ? findFlaggedTerms(row.title, row.description)
          : []
      }));

      const total = totalResult.rows[0].total;

      res.json({
        success: true,
        listings,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.max(Math.ceil(total / limit), 1)
        }
      });
    } catch (err) {
      console.error('Error fetching admin listings:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch listings for moderation'
      });
    }
  }
);

/*
  REMOVE A PROHIBITED LISTING (soft removal)
  The listing disappears from the marketplace but is kept for 30 days so an
  admin can restore it. Open reports about it are marked resolved.
  Body: { reason, note?, notify_seller? }
*/

app.delete(
  '/api/admin/listings/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const listingId = Number(req.params.id);

    if (!Number.isInteger(listingId) || listingId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid listing ID'
      });
    }

    const { reason } = req.body || {};

    if (!REMOVAL_REASONS.includes(reason)) {
      return res.status(400).json({
        success: false,
        error: 'Please choose a valid removal reason'
      });
    }

    const note = String(req.body.note || '').trim().slice(0, 500);
    const notifySeller = req.body.notify_seller !== false;

    let client;
    let notification = null;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const found = await client.query(
        `
          SELECT id, title, price, category, seller_id, seller_name, removed_at
          FROM listings
          WHERE id = $1
          FOR UPDATE
        `,
        [listingId]
      );

      if (found.rows.length === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          success: false,
          error: 'Listing not found. It may already have been deleted.'
        });
      }

      const listing = found.rows[0];

      if (listing.removed_at) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          success: false,
          error: 'This listing is already removed.'
        });
      }

      const canNotify =
        notifySeller &&
        listing.seller_id &&
        Number(listing.seller_id) !== Number(req.admin.id);

      await client.query(
        `
          UPDATE listings
          SET removed_at = NOW(),
              removed_reason = $2,
              removed_note = $3,
              removed_by = $4
          WHERE id = $1
        `,
        [listingId, reason, note || null, req.admin.id]
      );

      await client.query(
        `
          UPDATE listing_reports
          SET status = 'resolved',
              resolved_by = $2,
              resolved_at = NOW(),
              resolution_note = 'Listing removed'
          WHERE listing_id = $1 AND status = 'open'
        `,
        [listingId, req.admin.id]
      );

      await client.query(
        `
          INSERT INTO moderation_actions
            (
              action, listing_id, listing_title, listing_price, listing_category,
              seller_id, seller_name, admin_id, admin_name,
              reason, note, seller_notified
            )
          VALUES ('remove', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `,
        [
          listing.id,
          listing.title,
          listing.price,
          listing.category,
          listing.seller_id,
          listing.seller_name,
          req.admin.id,
          req.admin.full_name,
          reason,
          note || null,
          Boolean(canNotify)
        ]
      );

      if (canNotify) {
        const message =
          `Your listing "${listing.title}" was removed by UniLnk ` +
          `moderators because it breaks the marketplace rules ` +
          `(${reason}).` +
          (note ? ` Moderator note: ${note}` : '') +
          ' If you think this was a mistake, reply here.';

        const inserted = await client.query(
          `
            INSERT INTO chat_messages
              (sender_id, receiver_id, listing_id, message)
            VALUES ($1, $2, NULL, $3)
            RETURNING *
          `,
          [req.admin.id, listing.seller_id, message]
        );

        notification = {
          ...inserted.rows[0],
          sender_name: req.admin.full_name
        };
      }

      await client.query('COMMIT');

      if (notification) {
        pushToUser(notification.receiver_id, 'message', notification);
      }

      res.json({
        success: true,
        message: 'Listing removed',
        seller_notified: Boolean(notification)
      });
    } catch (err) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          console.error('Moderation rollback error:', rollbackError.message);
        }
      }

      console.error('Error removing listing:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to remove listing'
      });
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);

/*
  RESTORE A REMOVED LISTING
*/

app.put(
  '/api/admin/listings/:id/restore',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const listingId = Number(req.params.id);

    if (!Number.isInteger(listingId) || listingId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid listing ID'
      });
    }

    const note = String(req.body?.note || '').trim().slice(0, 500);
    const notifySeller = req.body?.notify_seller !== false;

    let client;
    let notification = null;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const found = await client.query(
        `
          SELECT id, title, price, category, seller_id, seller_name, removed_at
          FROM listings
          WHERE id = $1
          FOR UPDATE
        `,
        [listingId]
      );

      if (found.rows.length === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          success: false,
          error: 'Listing not found. It may have been permanently deleted.'
        });
      }

      const listing = found.rows[0];

      if (!listing.removed_at) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          success: false,
          error: 'This listing is not removed.'
        });
      }

      await client.query(
        `
          UPDATE listings
          SET removed_at = NULL,
              removed_reason = NULL,
              removed_note = NULL,
              removed_by = NULL
          WHERE id = $1
        `,
        [listingId]
      );

      const canNotify =
        notifySeller &&
        listing.seller_id &&
        Number(listing.seller_id) !== Number(req.admin.id);

      await client.query(
        `
          INSERT INTO moderation_actions
            (
              action, listing_id, listing_title, listing_price, listing_category,
              seller_id, seller_name, admin_id, admin_name,
              reason, note, seller_notified
            )
          VALUES ('restore', $1, $2, $3, $4, $5, $6, $7, $8, 'Restored', $9, $10)
        `,
        [
          listing.id,
          listing.title,
          listing.price,
          listing.category,
          listing.seller_id,
          listing.seller_name,
          req.admin.id,
          req.admin.full_name,
          note || null,
          Boolean(canNotify)
        ]
      );

      if (canNotify) {
        const inserted = await client.query(
          `
            INSERT INTO chat_messages
              (sender_id, receiver_id, listing_id, message)
            VALUES ($1, $2, $3, $4)
            RETURNING *
          `,
          [
            req.admin.id,
            listing.seller_id,
            listing.id,
            `Good news: your listing "${listing.title}" was reviewed again and is back on the marketplace.` +
              (note ? ` Moderator note: ${note}` : '')
          ]
        );

        notification = {
          ...inserted.rows[0],
          sender_name: req.admin.full_name
        };
      }

      await client.query('COMMIT');

      if (notification) {
        pushToUser(notification.receiver_id, 'message', notification);
      }

      res.json({ success: true, message: 'Listing restored' });
    } catch (err) {
      if (client) {
        await client.query('ROLLBACK').catch(() => {});
      }

      console.error('Error restoring listing:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to restore listing'
      });
    } finally {
      if (client) client.release();
    }
  }
);

/*
  MODERATION LOG
*/

app.get(
  '/api/admin/moderation-log',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { page, limit, offset } = parsePagination(req.query, 15, 50);

      const [totalResult, logResult] = await Promise.all([
        pool.query('SELECT COUNT(*)::int AS total FROM moderation_actions'),
        pool.query(
          `
            SELECT
              id, action, listing_id, listing_title, listing_price,
              listing_category, seller_id, seller_name, admin_name,
              reason, note, seller_notified, created_at
            FROM moderation_actions
            ORDER BY id DESC
            LIMIT $1 OFFSET $2
          `,
          [limit, offset]
        )
      ]);

      const total = totalResult.rows[0].total;

      res.json({
        success: true,
        entries: logResult.rows,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.max(Math.ceil(total / limit), 1)
        }
      });
    } catch (err) {
      console.error('Error fetching moderation log:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch moderation log'
      });
    }
  }
);

/*
  REPORTS QUEUE
  Query: status (open | resolved | dismissed | all), page, limit
*/

app.get(
  '/api/admin/reports',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const status = ['open', 'resolved', 'dismissed', 'all'].includes(
        req.query.status
      )
        ? req.query.status
        : 'open';

      const { page, limit, offset } = parsePagination(req.query, 15, 50);
      const params = [];
      let where = '';

      if (status !== 'all') {
        params.push(status);
        where = 'WHERE r.status = $1';
      }

      const baseFrom = `
        FROM listing_reports r
        JOIN listings l ON l.id = r.listing_id
        LEFT JOIN users u ON u.id = l.seller_id
        LEFT JOIN users rep ON rep.id = r.reporter_id
        ${where}
      `;

      const totalResult = await pool.query(
        `SELECT COUNT(*)::int AS total ${baseFrom}`,
        params
      );

      const result = await pool.query(
        `
          SELECT
            r.id, r.reason, r.details, r.status, r.created_at,
            r.resolved_at, r.resolution_note,
            l.id AS listing_id, l.title, l.price, l.category, l.image_url,
            l.is_sold, l.removed_at, l.seller_id,
            COALESCE(u.full_name, l.seller_name) AS seller_name,
            u.email AS seller_email,
            u.is_banned AS seller_banned,
            rep.full_name AS reporter_name,
            rep.student_id AS reporter_student_id,
            (
              SELECT COUNT(*)::int FROM listing_reports x
              WHERE x.listing_id = l.id AND x.status = 'open'
            ) AS open_reports_for_listing,
            (
              SELECT COUNT(*)::int FROM moderation_actions m
              WHERE m.seller_id = l.seller_id AND m.action = 'remove'
            ) AS seller_prior_removals
          ${baseFrom}
          ORDER BY ${
            status === 'open'
              ? 'r.created_at ASC'
              : 'r.resolved_at DESC NULLS LAST, r.id DESC'
          }
          LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        `,
        [...params, limit, offset]
      );

      const total = totalResult.rows[0].total;

      res.json({
        success: true,
        reports: result.rows,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.max(Math.ceil(total / limit), 1)
        }
      });
    } catch (err) {
      console.error('Error fetching reports:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch reports'
      });
    }
  }
);

/*
  DISMISS OR RESOLVE A REPORT
  Body: { action: 'dismiss' | 'resolve', note? }
  (Removing the listing resolves its reports automatically.)
*/

app.put(
  '/api/admin/reports/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const reportId = Number(req.params.id);
    const action = req.body?.action;
    const note = String(req.body?.note || '').trim().slice(0, 500);

    if (!Number.isInteger(reportId) || reportId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid report ID'
      });
    }

    if (!['dismiss', 'resolve'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: 'Action must be dismiss or resolve'
      });
    }

    try {
      const result = await pool.query(
        `
          UPDATE listing_reports
          SET status = $2,
              resolved_by = $3,
              resolved_at = NOW(),
              resolution_note = $4
          WHERE id = $1 AND status = 'open'
          RETURNING id
        `,
        [
          reportId,
          action === 'dismiss' ? 'dismissed' : 'resolved',
          req.admin.id,
          note || null
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Report not found or already handled'
        });
      }

      res.json({ success: true });
    } catch (err) {
      console.error('Error updating report:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to update report'
      });
    }
  }
);

/*
  USERS: list, suspend, unsuspend
*/

const BAN_REASONS = [
  'Repeated rule violations',
  'Scam or fraud',
  'Harassment',
  'Spam',
  'Other'
];

app.get(
  '/api/admin/users',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { search, status } = req.query;
      const { page, limit, offset } = parsePagination(req.query, 15, 50);
      const params = [];
      const conditions = [];

      if (status === 'banned') conditions.push('u.is_banned = TRUE');
      if (status === 'admins') conditions.push("u.role = 'admin'");

      if (search && String(search).trim()) {
        params.push(`%${escapeLike(String(search).trim().slice(0, 60))}%`);
        const i = params.length;
        conditions.push(`(
          u.full_name ILIKE $${i}
          OR u.email ILIKE $${i}
          OR u.student_id ILIKE $${i}
        )`);
      }

      const where =
        conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const totalResult = await pool.query(
        `SELECT COUNT(*)::int AS total FROM users u ${where}`,
        params
      );

      const result = await pool.query(
        `
          SELECT
            u.id, u.full_name, u.email, u.student_id, u.role,
            u.is_banned, u.ban_reason, u.banned_at, u.created_at,
            u.email_verified,
            (
              SELECT COUNT(*)::int FROM listings l
              WHERE l.seller_id = u.id AND l.is_sold = FALSE
                AND l.removed_at IS NULL
            ) AS active_listings,
            (
              SELECT COUNT(*)::int FROM moderation_actions m
              WHERE m.seller_id = u.id AND m.action = 'remove'
            ) AS removals,
            (
              SELECT COUNT(*)::int
              FROM listing_reports r
              JOIN listings l ON l.id = r.listing_id
              WHERE l.seller_id = u.id
            ) AS reports_received
          FROM users u
          ${where}
          ORDER BY u.id DESC
          LIMIT $${params.length + 1} OFFSET $${params.length + 2}
        `,
        [...params, limit, offset]
      );

      const total = totalResult.rows[0].total;

      res.json({
        success: true,
        users: result.rows,
        ban_reasons: BAN_REASONS,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.max(Math.ceil(total / limit), 1)
        }
      });
    } catch (err) {
      console.error('Error fetching users:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to fetch users'
      });
    }
  }
);

app.put(
  '/api/admin/users/:id/ban',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const userId = Number(req.params.id);
    const { reason } = req.body || {};
    const note = String(req.body?.note || '').trim().slice(0, 500);

    if (!Number.isInteger(userId) || userId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID'
      });
    }

    if (!BAN_REASONS.includes(reason)) {
      return res.status(400).json({
        success: false,
        error: 'Please choose a suspension reason'
      });
    }

    if (userId === Number(req.admin.id)) {
      return res.status(400).json({
        success: false,
        error: 'You cannot suspend your own account'
      });
    }

    try {
      const target = await pool.query(
        'SELECT id, full_name, role, is_banned FROM users WHERE id = $1',
        [userId]
      );

      if (target.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      if (target.rows[0].role === 'admin') {
        return res.status(400).json({
          success: false,
          error: 'Administrators cannot be suspended'
        });
      }

      if (target.rows[0].is_banned) {
        return res.status(409).json({
          success: false,
          error: 'This account is already suspended'
        });
      }

      await pool.query(
        `
          UPDATE users
          SET is_banned = TRUE, banned_at = NOW(), ban_reason = $2
          WHERE id = $1
        `,
        [userId, note ? `${reason}: ${note}` : reason]
      );

      await pool.query(
        `
          INSERT INTO moderation_actions
            (action, seller_id, seller_name, admin_id, admin_name, reason, note)
          VALUES ('ban', $1, $2, $3, $4, $5, $6)
        `,
        [
          userId,
          target.rows[0].full_name,
          req.admin.id,
          req.admin.full_name,
          reason,
          note || null
        ]
      );

      // Takes effect immediately: cached account state and live connections
      invalidateAccount(userId);
      closeUserStreams(userId);

      res.json({ success: true, message: 'Account suspended' });
    } catch (err) {
      console.error('Error suspending user:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to suspend account'
      });
    }
  }
);

app.put(
  '/api/admin/users/:id/unban',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId) || userId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID'
      });
    }

    try {
      const result = await pool.query(
        `
          UPDATE users
          SET is_banned = FALSE, banned_at = NULL, ban_reason = NULL
          WHERE id = $1 AND is_banned = TRUE
          RETURNING id, full_name
        `,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'This account is not suspended'
        });
      }

      await pool.query(
        `
          INSERT INTO moderation_actions
            (action, seller_id, seller_name, admin_id, admin_name, reason)
          VALUES ('unban', $1, $2, $3, $4, 'Suspension lifted')
        `,
        [userId, result.rows[0].full_name, req.admin.id, req.admin.full_name]
      );

      invalidateAccount(userId);

      res.json({ success: true, message: 'Account reinstated' });
    } catch (err) {
      console.error('Error unsuspending user:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to reinstate account'
      });
    }
  }
);

/*
  REMOVE AN ABUSIVE REVIEW
*/

app.delete(
  '/api/admin/reviews/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    const reviewId = Number(req.params.id);

    if (!Number.isInteger(reviewId) || reviewId < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid review ID'
      });
    }

    try {
      const result = await pool.query(
        `
          DELETE FROM seller_reviews r
          USING users u
          WHERE r.id = $1 AND u.id = r.seller_id
          RETURNING r.seller_id, r.rating, r.comment, u.full_name AS seller_name
        `,
        [reviewId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Review not found'
        });
      }

      const review = result.rows[0];

      await pool.query(
        `
          INSERT INTO moderation_actions
            (action, seller_id, seller_name, admin_id, admin_name, reason, note)
          VALUES ('review_remove', $1, $2, $3, $4, 'Review removed', $5)
        `,
        [
          review.seller_id,
          review.seller_name,
          req.admin.id,
          req.admin.full_name,
          `${review.rating} stars: ${String(review.comment || '').slice(0, 200)}`
        ]
      );

      res.json({ success: true });
    } catch (err) {
      console.error('Error removing review:', err);

      res.status(500).json({
        success: false,
        error: 'Unable to remove review'
      });
    }
  }
);

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get('/api/health', (req, res) => {
  res.json({
    status: 'Server is running!',
    timestamp: new Date().toISOString(),
    database: process.env.DATABASE_URL
      ? 'Configured'
      : 'Not configured'
  });
});

/* =========================================================
   START SERVER
   ========================================================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);

  console.log(
    `Database: ${
      process.env.DATABASE_URL
        ? 'Configured'
        : 'Not configured'
    }`
  );
});

/* =========================================================
   ERROR HANDLING
   ========================================================= */

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});
