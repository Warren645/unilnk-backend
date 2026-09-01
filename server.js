const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'unilnk_listings',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});

const upload = multer({ storage });

// PostgreSQL Pool Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Initialize Database
const initializeDatabase = async () => {
  try {
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        listing_id INTEGER REFERENCES listings(id),
        buyer_id INTEGER REFERENCES users(id),
        quantity INTEGER NOT NULL,
        total_price NUMERIC(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'RESERVED',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        transaction_id INTEGER REFERENCES transactions(id),
        sender_id INTEGER REFERENCES users(id),
        message_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

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

    await pool.query(`
      ALTER TABLE listings ADD COLUMN IF NOT EXISTS seller_name VARCHAR(255);
    `);

    console.log('✅ Database tables verified and created successfully!');
  } catch (err) {
    console.error('❌ Database initialization error:', err.message);
  }
};

initializeDatabase();

/* ================= AUTH ROUTES ================= */

app.post('/api/auth/register', async (req, res) => {
  const { full_name, email, password, student_id } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, student_id)
       VALUES ($1, $2, $3, $4) RETURNING id, full_name, email, student_id`,
      [full_name, email, password, student_id]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, student_id FROM users WHERE email = $1 AND password_hash = $2`,
      [email, password]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
    res.json({ success: true, user: result.rows[0], token: 'mock-jwt-token' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= LISTING ROUTES ================= */

app.get('/api/listings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.full_name as seller_name 
      FROM listings l 
      LEFT JOIN users u ON l.seller_id = u.id 
      ORDER BY l.id DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching listings:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/listings', upload.any(), async (req, res) => {
  try {
    let { title, description, price, quantity, category, campus, seller_id, course_code } = req.body;
    
    if (!title) {
      return res.status(400).json({ success: false, error: 'Title is required' });
    }
    if (!price) {
      return res.status(400).json({ success: false, error: 'Price is required' });
    }
    if (!seller_id) {
      return res.status(400).json({ success: false, error: 'Seller ID is required' });
    }

    // Get seller name
    let seller_name = null;
    try {
      const userResult = await pool.query(`SELECT full_name FROM users WHERE id = $1`, [seller_id]);
      if (userResult.rows.length > 0) {
        seller_name = userResult.rows[0].full_name;
      }
    } catch (err) {
      console.error('Error fetching seller name:', err);
    }

    const imageUrls = req.files && req.files.length > 0
      ? req.files.map(file => file.path)
      : [];

    const imagePayload = JSON.stringify(imageUrls);
    const courseCodeValue = course_code || 'GEN001';
    const campusValue = campus || 'Silverest Main Campus';
    const quantityValue = parseInt(quantity, 10) || 1;
    const priceValue = parseFloat(price) || 0;

    const result = await pool.query(
      `INSERT INTO listings (title, description, price, quantity, category, campus, seller_id, seller_name, image_url, course_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        title, 
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

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error creating listing:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/listings/:id', async (req, res) => {
  const { id } = req.params;
  const { price, quantity, title, description } = req.body;
  try {
    const result = await pool.query(
      `UPDATE listings 
       SET price = $1, quantity = $2, title = COALESCE($3, title), description = COALESCE($4, description)
       WHERE id = $5 RETURNING *`,
      [price, quantity, title, description, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Listing not found' });
    }
    res.json({ success: true, listing: result.rows[0] });
  } catch (err) {
    console.error('Error updating listing:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/listings/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM listings WHERE id = $1 RETURNING *`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Listing not found' });
    }
    res.json({ success: true, message: 'Listing deleted successfully' });
  } catch (err) {
    console.error('Error deleting listing:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= TRANSACTION ROUTES ================= */

app.post('/api/transactions/reserve', async (req, res) => {
  const { listing_id, buyer_id, quantity } = req.body;
  try {
    const listingRes = await pool.query(`SELECT price, quantity FROM listings WHERE id = $1`, [listing_id]);
    if (listingRes.rows.length === 0 || listingRes.rows[0].quantity < quantity) {
      return res.status(400).json({ success: false, error: 'Item out of stock' });
    }

    const price = listingRes.rows[0].price;
    const currentQty = listingRes.rows[0].quantity;
    const totalPrice = price * quantity;
    const newQuantity = currentQty - quantity;

    await pool.query(`UPDATE listings SET quantity = $1 WHERE id = $2`, [newQuantity, listing_id]);

    const txnRes = await pool.query(
      `INSERT INTO transactions (listing_id, buyer_id, quantity, total_price, status)
       VALUES ($1, $2, $3, $4, 'RESERVED') RETURNING *`,
      [listing_id, buyer_id, quantity, totalPrice]
    );

    res.json({ success: true, transaction: txnRes.rows[0] });
  } catch (err) {
    console.error('Error reserving item:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/transactions/handshake', async (req, res) => {
  const { transaction_id } = req.body;
  try {
    const result = await pool.query(
      `UPDATE transactions SET status = 'VERIFIED' WHERE id = $1 RETURNING *`,
      [transaction_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Transaction ID not found' });
    }

    const transaction = result.rows[0];
    await pool.query(`DELETE FROM listings WHERE id = $1`, [transaction.listing_id]);

    res.json({ success: true, transaction: transaction, message: 'Transaction verified and listing removed from marketplace.' });
  } catch (err) {
    console.error('Error verifying handshake:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/users/:userId/dashboard', async (req, res) => {
  const { userId } = req.params;
  try {
    const purchases = await pool.query(
      `SELECT t.id as transaction_id, l.title, t.total_price, t.status 
       FROM transactions t JOIN listings l ON t.listing_id = l.id 
       WHERE t.buyer_id = $1`,
      [userId]
    );
    res.json({ success: true, purchases: purchases.rows, sales: [] });
  } catch (err) {
    console.error('Error fetching dashboard:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/users/:userId/listings', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM listings WHERE seller_id = $1 ORDER BY id DESC`,
      [userId]
    );
    res.json({ success: true, listings: result.rows });
  } catch (err) {
    console.error('Error fetching seller listings:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= TRANSACTION MESSAGES ================= */

app.get('/api/transactions/:txnId/messages', async (req, res) => {
  const { txnId } = req.params;
  try {
    const result = await pool.query(
      `SELECT m.id, m.message_text, u.full_name as sender_name, m.created_at
       FROM messages m JOIN users u ON m.sender_id = u.id
       WHERE m.transaction_id = $1 ORDER BY m.created_at ASC`,
      [txnId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/transactions/:txnId/messages', async (req, res) => {
  const { txnId } = req.params;
  const { sender_id, message_text } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO messages (transaction_id, sender_id, message_text)
       VALUES ($1, $2, $3) RETURNING *`,
      [txnId, sender_id, message_text]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= CHAT ROUTES ================= */

// Get all conversations for a user
app.get('/api/chat/conversations/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(`
      SELECT 
        u.id as user_id,
        u.full_name as user_name,
        u.email,
        u.student_id,
        (
          SELECT message 
          FROM chat_messages 
          WHERE (sender_id = $1 AND receiver_id = u.id) 
             OR (sender_id = u.id AND receiver_id = $1)
          ORDER BY created_at DESC 
          LIMIT 1
        ) as last_message,
        (
          SELECT created_at 
          FROM chat_messages 
          WHERE (sender_id = $1 AND receiver_id = u.id) 
             OR (sender_id = u.id AND receiver_id = $1)
          ORDER BY created_at DESC 
          LIMIT 1
        ) as last_message_time,
        (
          SELECT COUNT(*) 
          FROM chat_messages 
          WHERE receiver_id = $1 AND sender_id = u.id AND is_read = FALSE
        ) as unread_count,
        (
          SELECT l.title 
          FROM chat_messages cm
          JOIN listings l ON cm.listing_id = l.id
          WHERE (cm.sender_id = $1 AND cm.receiver_id = u.id) 
             OR (cm.sender_id = u.id AND cm.receiver_id = $1)
          ORDER BY cm.created_at DESC 
          LIMIT 1
        ) as listing_title
      FROM users u
      WHERE u.id IN (
        SELECT DISTINCT 
          CASE 
            WHEN sender_id = $1 THEN receiver_id 
            ELSE sender_id 
          END as other_user
        FROM chat_messages 
        WHERE sender_id = $1 OR receiver_id = $1
      )
      AND u.id != $1
      ORDER BY last_message_time DESC NULLS LAST
    `, [userId]);
    
    res.json({ success: true, conversations: result.rows });
  } catch (err) {
    console.error('Error fetching conversations:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get total unread count
app.get('/api/chat/unread/total/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT COUNT(*) as total_unread 
       FROM chat_messages 
       WHERE receiver_id = $1 AND is_read = FALSE`,
      [userId]
    );
    res.json({ success: true, total_unread: parseInt(result.rows[0].total_unread) });
  } catch (err) {
    console.error('Error getting unread count:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Mark messages as read
app.put('/api/chat/mark-read/:userId/:otherUserId', async (req, res) => {
  const { userId, otherUserId } = req.params;
  try {
    await pool.query(
      `UPDATE chat_messages 
       SET is_read = TRUE 
       WHERE receiver_id = $1 AND sender_id = $2 AND is_read = FALSE`,
      [userId, otherUserId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Error marking messages as read:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get chat messages
app.get('/api/chat/messages/:userId/:otherUserId', async (req, res) => {
  const { userId, otherUserId } = req.params;
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  
  try {
    const result = await pool.query(
      `SELECT cm.*, 
        u1.full_name as sender_name, 
        u2.full_name as receiver_name,
        l.title as listing_title,
        l.id as listing_id
       FROM chat_messages cm
       LEFT JOIN users u1 ON cm.sender_id = u1.id
       LEFT JOIN users u2 ON cm.receiver_id = u2.id
       LEFT JOIN listings l ON cm.listing_id = l.id
       WHERE (cm.sender_id = $1 AND cm.receiver_id = $2)
          OR (cm.sender_id = $2 AND cm.receiver_id = $1)
       ORDER BY cm.created_at ASC
       LIMIT $3 OFFSET $4`,
      [userId, otherUserId, limit, offset]
    );
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    console.error('Error fetching chat messages:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Send chat message
app.post('/api/chat/send', async (req, res) => {
  const { sender_id, receiver_id, listing_id, message } = req.body;
  
  if (!sender_id || !receiver_id || !message) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO chat_messages (sender_id, receiver_id, listing_id, message)
       VALUES ($1, $2, $3, $4) 
       RETURNING *`,
      [sender_id, receiver_id, listing_id || null, message]
    );
    
    const senderResult = await pool.query(
      `SELECT full_name FROM users WHERE id = $1`,
      [sender_id]
    );
    
    res.json({ 
      success: true, 
      message: {
        ...result.rows[0],
        sender_name: senderResult.rows[0]?.full_name || 'Student'
      } 
    });
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= HEALTH CHECK ================= */

app.get('/api/health', (req, res) => {
  res.json({ 
    status: '✅ Server is running!', 
    timestamp: new Date().toISOString(),
    database: process.env.DATABASE_URL ? 'Connected' : 'Not connected'
  });
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Render PostgreSQL' : 'Local PostgreSQL'}`);
});
