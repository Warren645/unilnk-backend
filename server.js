
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

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

app.use(express.json());

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
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp']
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
  let client;

  try {
    client = await pool.connect();

    await client.query('BEGIN');

    /*
      Chat messages reference listings through a foreign key.
      Clear the listing reference for messages associated with
      listings that are due for deletion.
      The messages themselves are preserved.
    */

    await client.query(`
      UPDATE chat_messages
      SET listing_id = NULL
      WHERE listing_id IN (
        SELECT id
        FROM listings
        WHERE is_sold = TRUE
          AND sold_at IS NOT NULL
          AND sold_at <= CURRENT_TIMESTAMP - INTERVAL '5 days'
      );
    `);

    const result = await client.query(`
      DELETE FROM listings
      WHERE is_sold = TRUE
        AND sold_at IS NOT NULL
        AND sold_at <= CURRENT_TIMESTAMP - INTERVAL '5 days';
    `);

    await client.query('COMMIT');

    if (result.rowCount > 0) {
      console.log(
        `Automatically deleted ${result.rowCount} sold listing(s).`
      );
    }
  } catch (err) {
    if (client) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        console.error(
          'Cleanup rollback error:',
          rollbackError.message
        );
      }
    }

    console.error(
      'Sold-listing cleanup error:',
      err.message
    );
  } finally {
    if (client) {
      client.release();
    }
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

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 6 characters long'
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
        SELECT id
        FROM users
        WHERE LOWER(email) = $1
      `,
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'An account with this email already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
        INSERT INTO users
          (full_name, email, password_hash, student_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id, full_name, email, student_id
      `,
      [
        full_name.trim(),
        normalizedEmail,
        passwordHash,
        student_id.trim()
      ]
    );

    const user = result.rows[0];

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

    res.status(201).json({
      success: true,
      user,
      token
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

    const result = await pool.query(
      `
        SELECT
          id,
          full_name,
          email,
          password_hash,
          student_id
        FROM users
        WHERE LOWER(email) = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
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
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const user = {
      id: dbUser.id,
      full_name: dbUser.full_name,
      email: dbUser.email,
      student_id: dbUser.student_id
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

const authenticateToken = (req, res, next) => {
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

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (err) {
    console.error('JWT verification error:', err.message);

    return res.status(403).json({
      success: false,
      error: 'Invalid or expired authentication token'
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

app.get('/api/listings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        l.*,
        u.full_name AS seller_name
      FROM listings l
      LEFT JOIN users u
        ON l.seller_id = u.id
      WHERE l.is_sold = FALSE
      ORDER BY l.id DESC
    `);

    res.json({
      success: true,
      data: result.rows
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
      const result = await pool.query(
        `
          DELETE FROM listings
          WHERE id = $1
            AND seller_id = $2
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
            ) AS listing_title

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
      const result = await pool.query(
        `
          SELECT
            cm.*,
            u1.full_name AS sender_name,
            u2.full_name AS receiver_name,
            l.title AS listing_title,
            l.id AS listing_id
          FROM chat_messages cm
          LEFT JOIN users u1 ON cm.sender_id = u1.id
          LEFT JOIN users u2 ON cm.receiver_id = u2.id
          LEFT JOIN listings l ON cm.listing_id = l.id
          WHERE
            (cm.sender_id = $1 AND cm.receiver_id = $2)
            OR
            (cm.sender_id = $2 AND cm.receiver_id = $1)
          ORDER BY cm.created_at ASC
          LIMIT $3
          OFFSET $4
        `,
        [userId, otherUserId, limit, offset]
      );

      res.json({
        success: true,
        messages: result.rows
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

    if (Number(receiver_id) === Number(sender_id)) {
      return res.status(400).json({
        success: false,
        error: 'You cannot send a message to yourself'
      });
    }

    try {
      const recipientResult = await pool.query(
        'SELECT id FROM users WHERE id = $1',
        [receiver_id]
      );

      if (recipientResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Recipient not found'
        });
      }

      /*
        If a listing ID is supplied, verify that it exists.
        Sold listings can still be discussed through existing chats.
      */

      if (listing_id) {
        const listingResult = await pool.query(
          'SELECT id FROM listings WHERE id = $1',
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
        `
          SELECT full_name
          FROM users
          WHERE id = $1
        `,
        [sender_id]
      );

      res.json({
        success: true,
        message: {
          ...result.rows[0],
          sender_name:
            senderResult.rows[0]?.full_name || 'Student'
        }
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
