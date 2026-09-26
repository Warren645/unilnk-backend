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
    '⚠️ JWT_SECRET is not configured. Authentication routes will reject requests.'
  );
}

/* =========================================================
   CORS
   ========================================================= */

app.use(
  cors({
    origin: '*',
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

    allowed_formats: [
      'jpg',
      'png',
      'jpeg',
      'webp'
    ]
  }
});

/*
  Maximum:
  - 5 images per listing
  - 5 MB per image
*/

const upload = multer({
  storage,

  limits: {
    files: 5,
    fileSize: 5 * 1024 * 1024
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    console.log(
      '✅ Database tables verified and created successfully!'
    );
  } catch (err) {
    console.error(
      '❌ Database initialization error:',
      err.message
    );
  }
};

initializeDatabase();

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

  /* ================= VALIDATION ================= */

  if (
    !full_name?.trim() ||
    !email?.trim() ||
    !password ||
    !student_id?.trim()
  ) {
    return res.status(400).json({
      success: false,
      error:
        'Full name, email, password and student ID are required'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      error:
        'Password must be at least 6 characters long'
    });
  }

  if (!process.env.JWT_SECRET) {
    console.error(
      'JWT_SECRET is missing from environment variables'
    );

    return res.status(500).json({
      success: false,
      error:
        'Server authentication is not configured'
    });
  }

  try {
    /* ================= NORMALIZE EMAIL ================= */

    const normalizedEmail =
      email.trim().toLowerCase();

    /* ================= CHECK DUPLICATE ================= */

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
        error:
          'An account with this email already exists'
      });
    }

    /* ================= HASH PASSWORD ================= */

    const passwordHash =
      await bcrypt.hash(password, 12);

    /* ================= CREATE USER ================= */

    const result = await pool.query(
      `
        INSERT INTO users
        (
          full_name,
          email,
          password_hash,
          student_id
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4
        )

        RETURNING
          id,
          full_name,
          email,
          student_id
      `,
      [
        full_name.trim(),
        normalizedEmail,
        passwordHash,
        student_id.trim()
      ]
    );

    const user = result.rows[0];

    /* ================= CREATE JWT ================= */

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

    /* ================= RESPONSE ================= */

    res.status(201).json({
      success: true,
      user,
      token
    });

  } catch (err) {

    console.error(
      'Registration error:',
      err
    );

    if (err.code === '23505') {
      return res.status(409).json({
        success: false,
        error:
          'An account with this email already exists'
      });
    }

    res.status(500).json({
      success: false,
      error:
        'Unable to create account'
    });
  }
});


/*
  LOGIN
  POST /api/auth/login
*/

app.post('/api/auth/login', async (req, res) => {

  const {
    email,
    password
  } = req.body;

  /* ================= VALIDATION ================= */

  if (
    !email?.trim() ||
    !password
  ) {

    return res.status(400).json({
      success: false,
      error:
        'Email and password are required'
    });
  }

  if (!process.env.JWT_SECRET) {

    console.error(
      'JWT_SECRET is missing from environment variables'
    );

    return res.status(500).json({
      success: false,
      error:
        'Server authentication is not configured'
    });
  }

  try {

    /* ================= NORMALIZE EMAIL ================= */

    const normalizedEmail =
      email.trim().toLowerCase();

    /* ================= FIND USER ================= */

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
        error:
          'Invalid email or password'
      });
    }

    const dbUser =
      result.rows[0];

    let passwordMatches = false;

    /* =====================================================
       NEW USERS
       PASSWORD IS BCRYPT HASHED
       ===================================================== */

    if (
      dbUser.password_hash?.startsWith('$2')
    ) {

      passwordMatches =
        await bcrypt.compare(
          password,
          dbUser.password_hash
        );

    } else {

      /* ===================================================
         OLD USERS

         This compatibility section allows accounts
         created before this security update to log in.

         After successful login, their password is
         immediately converted to a bcrypt hash.
         =================================================== */

      passwordMatches =
        dbUser.password_hash === password;

      if (passwordMatches) {

        const upgradedHash =
          await bcrypt.hash(
            password,
            12
          );

        await pool.query(
          `
            UPDATE users

            SET password_hash = $1

            WHERE id = $2
          `,
          [
            upgradedHash,
            dbUser.id
          ]
        );

        console.log(
          `🔐 Upgraded legacy password hash for user ${dbUser.id}`
        );
      }
    }

    /* ================= INVALID PASSWORD ================= */

    if (!passwordMatches) {

      return res.status(401).json({
        success: false,
        error:
          'Invalid email or password'
      });
    }

    /* ================= USER OBJECT ================= */

    const user = {
      id: dbUser.id,
      full_name: dbUser.full_name,
      email: dbUser.email,
      student_id: dbUser.student_id
    };

    /* ================= CREATE JWT ================= */

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

    /* ================= RESPONSE ================= */

    res.json({
      success: true,
      user,
      token
    });

  } catch (err) {

    console.error(
      'Login error:',
      err
    );

    res.status(500).json({
      success: false,
      error:
        'Unable to log in'
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

    console.error(
      'JWT verification error:',
      err.message
    );

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
  GET ALL LISTINGS
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

      ORDER BY l.id DESC
    `);

    res.json({
      success: true,
      data: result.rows
    });

  } catch (err) {

    console.error(
      'Error fetching listings:',
      err
    );

    res.status(500).json({
      success: false,
      error:
        err.message
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

      let {
        title,
        description,
        price,
        quantity,
        category,
        campus,
        course_code
      } = req.body;

      /* ================= VALIDATION ================= */

      if (!title?.trim()) {

        return res.status(400).json({
          success: false,
          error:
            'Title is required'
        });
      }

      if (
        price === undefined ||
        price === null ||
        price === ''
      ) {

        return res.status(400).json({
          success: false,
          error:
            'Price is required'
        });
      }
       //Get the seller ID from the verified JWT.
       const seller_id = req.user.id;

      if (!seller_id) {

        return res.status(400).json({
          success: false,
          error:
            'Seller ID is required'
        });
      }

      /* ================= GET SELLER ================= */

      let seller_name = null;

      try {

        const userResult =
          await pool.query(
            `
              SELECT full_name
              FROM users
              WHERE id = $1
            `,
            [seller_id]
          );

        if (
          userResult.rows.length > 0
        ) {

          seller_name =
            userResult.rows[0].full_name;
        }

      } catch (err) {

        console.error(
          'Error fetching seller name:',
          err
        );
      }

      /* ================= IMAGES ================= */

      const imageUrls =
        req.files &&
        req.files.length > 0
          ? req.files.map(
              file => file.path
            )
          : [];

      const imagePayload =
        JSON.stringify(imageUrls);

      /* ================= DEFAULTS ================= */

      const courseCodeValue =
        course_code || 'GEN001';

      const campusValue =
        campus ||
        'Silverest Main Campus';

      const quantityValue =
        parseInt(quantity, 10) || 1;

      const priceValue =
        parseFloat(price) || 0;

      /* ================= INSERT ================= */

      const result =
        await pool.query(
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

            VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              $9,
              $10
            )

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

      console.error(
        'Error creating listing:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
      });
    }
  }
);


/*
  UPDATE LISTING
*/

app.put(
   '/api/listings/:id', 
   authenticateToken,
   async (req, res) => {

  const { id } =
    req.params;

  const {
    price,
    quantity,
    title,
    description
  } = req.body;

  try {

    const result =
      await pool.query(
        `
          UPDATE listings

          SET
            price = $1,
            quantity = $2,
            title = COALESCE($3, title),
            description = COALESCE($4, description)

          WHERE id = $5 AND seller_id = $6

          RETURNING *
        `,
        [
          price,
          quantity,
          title,
          description,
          id,
           req.user.id
        ]
      );

    if (
      result.rows.length === 0
    ) {

      return res.status(404).json({
        success: false,
        error:
          'Listing not found or you are not authorized to edit it'
      });
    }

    res.json({
      success: true,
      listing:
        result.rows[0]
    });

  } catch (err) {

    console.error(
      'Error updating listing:',
      err
    );

    res.status(500).json({
      success: false,
      error:
        err.message
    });
  }
});


/*
  DELETE LISTING
*/

app.delete(
   '/api/listings/:id',
   authenticateToken,
   async (req, res) => {

  const { id } =
    req.params;

  try {

    const result =
      await pool.query(
        `
          DELETE FROM listings

          WHERE id = $1 AND seller_id = $2


          RETURNING *
        `,
        [id,req.user.id]
      );

    if (
      result.rows.length === 0
    ) {

      return res.status(404).json({
        success: false,
        error:
          'Listing not found or you are not authorized to delete it'
      });
    }

    res.json({
      success: true,
      message:
        'Listing deleted successfully'
    });

  } catch (err) {

    console.error(
      'Error deleting listing:',
      err
    );

    res.status(500).json({
      success: false,
      error:
        err.message
    });
  }
});


/*
  GET USER LISTINGS
*/

app.get(
  '/api/users/:userId/listings',
   authenticateToken,
  async (req, res) => {

    const {
      userId
    } = req.params;
     if (Number(userId) !== Number(req.user.id)) {
  return res.status(403).json({
    success: false,
    error: 'You are not authorized to access this account'
  });
}

    try {

      const result =
        await pool.query(
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
        listings:
          result.rows
      });

    } catch (err) {

      console.error(
        'Error fetching seller listings:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
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

    const {
      userId
    } = req.params;
     if (Number(userId) !== Number(req.user.id)) {
  return res.status(403).json({
    success: false,
    error: 'You are not authorized to access this account'
  });
}

    try {

      const result =
        await pool.query(
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
                  (
                    sender_id = $1
                    AND receiver_id = u.id
                  )

                  OR

                  (
                    sender_id = u.id
                    AND receiver_id = $1
                  )

                ORDER BY created_at DESC

                LIMIT 1

              ) AS last_message,

              (
                SELECT created_at

                FROM chat_messages

                WHERE
                  (
                    sender_id = $1
                    AND receiver_id = u.id
                  )

                  OR

                  (
                    sender_id = u.id
                    AND receiver_id = $1
                  )

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

                JOIN listings l
                  ON cm.listing_id = l.id

                WHERE
                  (
                    cm.sender_id = $1
                    AND cm.receiver_id = u.id
                  )

                  OR

                  (
                    cm.sender_id = u.id
                    AND cm.receiver_id = $1
                  )

                ORDER BY cm.created_at DESC

                LIMIT 1

              ) AS listing_title

            FROM users u

            WHERE u.id IN (

              SELECT DISTINCT

                CASE

                  WHEN sender_id = $1
                    THEN receiver_id

                  ELSE sender_id

                END AS other_user

              FROM chat_messages

              WHERE
                sender_id = $1
                OR receiver_id = $1
            )

            AND u.id != $1

            ORDER BY
              last_message_time DESC NULLS LAST
          `,
          [userId]
        );

      res.json({
        success: true,
        conversations:
          result.rows
      });

    } catch (err) {

      console.error(
        'Error fetching conversations:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
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

    const {
      userId
    } = req.params;
     if (Number(userId) !== Number(req.user.id)) {
  return res.status(403).json({
    success: false,
    error: 'You are not authorized to access this account'
  });
}

    try {

      const result =
        await pool.query(
          `
            SELECT COUNT(*) AS total_unread

            FROM chat_messages

            WHERE
              receiver_id = $1
              AND is_read = FALSE
          `,
          [userId]
        );

      res.json({
        success: true,
        total_unread:
          parseInt(
            result.rows[0].total_unread
          )
      });

    } catch (err) {

      console.error(
        'Error getting unread count:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
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

    const {
      userId,
      otherUserId
    } = req.params;
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
        [
          userId,
          otherUserId
        ]
      );

      res.json({
        success: true
      });

    } catch (err) {

      console.error(
        'Error marking messages as read:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
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

    const {
      userId,
      otherUserId
    } = req.params;
     if (Number(userId) !== Number(req.user.id)) {
  return res.status(403).json({
    success: false,
    error: 'You are not authorized to access this account'
  });
}

    const limit =
      parseInt(req.query.limit) || 50;

    const offset =
      parseInt(req.query.offset) || 0;

    try {

      const result =
        await pool.query(
          `
            SELECT

              cm.*,

              u1.full_name AS sender_name,

              u2.full_name AS receiver_name,

              l.title AS listing_title,

              l.id AS listing_id

            FROM chat_messages cm

            LEFT JOIN users u1
              ON cm.sender_id = u1.id

            LEFT JOIN users u2
              ON cm.receiver_id = u2.id

            LEFT JOIN listings l
              ON cm.listing_id = l.id

            WHERE

              (
                cm.sender_id = $1
                AND cm.receiver_id = $2
              )

              OR

              (
                cm.sender_id = $2
                AND cm.receiver_id = $1
              )

            ORDER BY
              cm.created_at ASC

            LIMIT $3

            OFFSET $4
          `,
          [
            userId,
            otherUserId,
            limit,
            offset
          ]
        );

      res.json({
        success: true,
        messages:
          result.rows
      });

    } catch (err) {

      console.error(
        'Error fetching chat messages:',
        err
      );

      res.status(500).json({
        success: false,
        error:
          err.message
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

      const result = await pool.query(
        `
          INSERT INTO chat_messages
          (
            sender_id,
            receiver_id,
            listing_id,
            message
          )
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

app.get(
  '/api/health',
  (req, res) => {

    res.json({
      status:
        '✅ Server is running!',

      timestamp:
        new Date().toISOString(),

      database:
        process.env.DATABASE_URL
          ? 'Connected'
          : 'Not connected'
    });
  }
);


/* =========================================================
   START SERVER
   ========================================================= */

const PORT =
  process.env.PORT || 5000;

app.listen(
  PORT,
  () => {

    console.log(
      `🚀 Server running on port ${PORT}`
    );

    console.log(
      `📊 Database: ${
        process.env.DATABASE_URL
          ? 'Render PostgreSQL'
          : 'Local PostgreSQL'
      }`
    );
  }
);


/* =========================================================
   ERROR HANDLING
   ========================================================= */

process.on(
  'uncaughtException',
  (err) => {

    console.error(
      '❌ Uncaught Exception:',
      err
    );
  }
);

process.on(
  'unhandledRejection',
  (err) => {

    console.error(
      '❌ Unhandled Rejection:',
      err
    );
  }
);
