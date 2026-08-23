const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Serve uploaded static files
app.use('/uploads', express.static(uploadsDir));

// PostgreSQL Pool Connection
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'unilnk_db',
  password: 'Warren#@22',
  port: 5432,
});

// Auto-Ensure 'campus' column exists in listings table on server startup
pool.query(`
  ALTER TABLE listings ADD COLUMN IF NOT EXISTS campus VARCHAR(255) DEFAULT 'Silverest Main Campus';
`).catch(err => console.error('Column migration check error:', err.message));

// Configure Multer Storage for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'));
  },
});

const upload = multer({ storage });

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
    const result = await pool.query(`SELECT * FROM listings ORDER BY id DESC`);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create Listing Endpoint with Campus Column Fixed
app.post('/api/listings', upload.any(), async (req, res) => {
  let { title, description, price, quantity, category, campus, seller_id, course_code } = req.body;
  
  if (!seller_id) {
    return res.status(400).json({ success: false, error: 'Seller ID is required' });
  }

  // Regex check for valid PostgreSQL UUID
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  
  // If seller_id is an integer string like "5", resolve the true UUID from PostgreSQL
  if (!uuidRegex.test(seller_id)) {
    try {
      const userLookup = await pool.query(`SELECT id FROM users LIMIT 1`);
      if (userLookup.rows.length > 0) {
        seller_id = userLookup.rows[0].id;
      } else {
        return res.status(400).json({ success: false, error: 'User UUID not found in database. Please log out and log in again.' });
      }
    } catch (lookupErr) {
      return res.status(500).json({ success: false, error: 'Failed to resolve user account UUID.' });
    }
  }

  // Collect uploaded file URLs
  const imageUrls = req.files && req.files.length > 0
    ? req.files.map(file => `http://localhost:5000/uploads/${file.filename}`)
    : [];

  const imagePayload = JSON.stringify(imageUrls);
  const courseCodeValue = course_code || 'GEN001';
  const campusValue = campus || 'Silverest Main Campus';

  try {
    const result = await pool.query(
      `INSERT INTO listings (title, description, price, quantity, category, campus, seller_id, image_url, course_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        title, 
        description, 
        parseFloat(price) || 0, 
        parseInt(quantity, 10) || 1, 
        category, 
        campusValue,
        seller_id, 
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

/* ================= TRANSACTION & CHAT ROUTES ================= */

app.post('/api/transactions/reserve', async (req, res) => {
  const { listing_id, buyer_id, quantity } = req.body;
  try {
    const listingRes = await pool.query(`SELECT price, quantity FROM listings WHERE id = $1`, [listing_id]);
    if (listingRes.rows.length === 0 || listingRes.rows[0].quantity < quantity) {
      return res.status(400).json({ success: false, error: 'Item out of stock' });
    }

    const price = listingRes.rows[0].price;
    const totalPrice = price * quantity;

    await pool.query(`UPDATE listings SET quantity = quantity - $1 WHERE id = $2`, [quantity, listing_id]);

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
    res.json({ success: true, transaction: result.rows[0] });
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

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));