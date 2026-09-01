const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
app.use(cors());
app.use(express.json());

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer to use Cloudinary Storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'unilnk_listings',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});

const upload = multer({ storage });

// PostgreSQL Pool Connection
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: 'postgres',
        host: 'localhost',
        database: 'unilnk_db',
        password: 'Warren#@22',
        port: 5432,
      }
);

// Auto-Create Database Tables
const initializeDatabase = async () => {
  try {
    // Add chat_messages table for direct seller-buyer chat
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        student_id VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

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

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        listing_id INTEGER REFERENCES listings(id),
        buyer_id INTEGER REFERENCES users(id),
        quantity INTEGER NOT NULL,
        total_price NUMERIC(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'RESERVED',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        transaction_id INTEGER REFERENCES transactions(id),
        sender_id INTEGER REFERENCES users(id),
        message_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- NEW: Direct chat messages table (for seller-buyer chat without reservation)
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        listing_id INTEGER REFERENCES listings(id),
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Add seller_name to listings if not exists
      ALTER TABLE listings ADD COLUMN IF NOT EXISTS seller_name VARCHAR(255);
    `);
    console.log('Database tables verified and created successfully!');
  } catch (err) {
    console.error('Database initialization error:', err.message);
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
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= LISTING ROUTES ================= */

app.get('/api/listings', async (req, res) => {
  try {
    // Include seller_name in the query
    const result = await pool.query(`
      SELECT l.*, u.full_name as seller_name 
      FROM listings l 
      LEFT JOIN users u ON l.seller_id = u.id 
      ORDER BY l.id DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/listings', upload.any(), async (req, res) => {
  let { title, description, price, quantity, category, campus, seller_id, course_code } = req.body;
  
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

  try {
    const result = await pool.query(
      `INSERT INTO listings (title, description, price, quantity, category, campus, seller_id, seller_name, image_url, course_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        title, 
        description, 
        parseFloat(price) || 0, 
        parseInt(quantity, 10) || 1, 
        category, 
        campusValue,
        seller_id, 
        seller_name,
        imagePayload, 
        courseCodeValue
      ]
    );
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Database Error during listing creation:', err.message);
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
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= CHAT ROUTES (NEW - For Direct Seller-Buyer Chat) ================= */

// Get chat history between two users
app.get('/api/chat/:userId/:sellerId', async (req, res) => {
  const { userId, sellerId } = req.params;
  try {
    const result = await pool.query(
      `SELECT cm.*, 
        u1.full_name as sender_name, 
        u2.full_name as receiver_name,
        l.title as listing_title
       FROM chat_messages cm
       LEFT JOIN users u1 ON cm.sender_id = u1.id
       LEFT JOIN users u2 ON cm.receiver_id = u2.id
       LEFT JOIN listings l ON cm.listing_id = l.id
       WHERE (cm.sender_id = $1 AND cm.receiver_id = $2)
          OR (cm.sender_id = $2 AND cm.receiver_id = $1)
       ORDER BY cm.created_at ASC`,
      [userId, sellerId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    console.error('Error fetching chat messages:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Send a chat message
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
    
    // Get sender name for response
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

// Mark messages as read
app.put('/api/chat/mark-read', async (req, res) => {
  const { userId, sellerId } = req.body;
  try {
    await pool.query(
      `UPDATE chat_messages SET is_read = TRUE 
       WHERE receiver_id = $1 AND sender_id = $2 AND is_read = FALSE`,
      [userId, sellerId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get unread message count
app.get('/api/chat/unread/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT COUNT(*) as unread_count 
       FROM chat_messages 
       WHERE receiver_id = $1 AND is_read = FALSE`,
      [userId]
    );
    res.json({ success: true, unread_count: parseInt(result.rows[0].unread_count) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= TRANSACTION MESSAGES (Existing) ================= */

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
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ================= SELLER INVENTORY ROUTES ================= */

app.get('/api/users/:userId/listings', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM listings WHERE seller_id = $1 ORDER BY id DESC`,
      [userId]
    );
    res.json({ success: true, listings: result.rows });
  } catch (err) {
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
    res.status(500).json({ success: false, error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
