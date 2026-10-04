const multer = require('multer');

const PROFILE_FIELDS = 'id, full_name, email, student_id, role, bio, campus, programme, avatar_url, created_at';
const CAMPUSES = ['', 'Silverest Main Campus', 'Pioneer Campus', 'Mass Media Campus'];
function validateProfile(body) {
  const limits = { full_name: 100, bio: 500, campus: 100, programme: 120 };
  const result = {};
  for (const [key, limit] of Object.entries(limits)) {
    if (typeof body?.[key] !== 'string') throw new Error(`Invalid ${key.replace('_', ' ')}`);
    result[key] = body[key].trim();
    if (result[key].length > limit) throw new Error(`${key.replace('_', ' ')} must be ${limit} characters or fewer`);
  }
  if (result.full_name.length < 2) throw new Error('Name must be at least 2 characters');
  if (!CAMPUSES.includes(result.campus)) throw new Error('Choose a supported campus');
  return result;
}
function isImage(buffer) {
  return (buffer.length >= 3 && buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255) ||
    (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) ||
    (buffer.length >= 12 && buffer.toString('ascii',0,4) === 'RIFF' && buffer.toString('ascii',8,12) === 'WEBP');
}

function registerProfileRoutes(app, { pool, authenticateToken, cloudinary, bcrypt, validatePassword }) {
  const photoUpload = multer({ storage: multer.memoryStorage(), limits: { files: 1, fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => cb(null, ['image/jpeg','image/png','image/webp'].includes(file.mimetype)) }).single('avatar');
  const cleanPhoto = async (id) => {
    if (!id) return;
    try { await cloudinary.uploader.destroy(id); } catch (error) { console.error('Profile image cleanup failed:', error.message); }
  };
  app.put('/api/profile', authenticateToken, async (req, res) => {
    let values;
    try { values = validateProfile(req.body); } catch (error) { return res.status(400).json({success:false,error:error.message}); }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(`UPDATE users SET full_name=$1, bio=$2, campus=$3, programme=$4 WHERE id=$5 RETURNING ${PROFILE_FIELDS}`,
        [values.full_name, values.bio, values.campus, values.programme, req.user.id]);
      await client.query('UPDATE listings SET seller_name=$1 WHERE seller_id=$2', [values.full_name,req.user.id]);
      await client.query('COMMIT');
      res.json({success:true,user:result.rows[0]});
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Profile update failed:', error.message);
      res.status(500).json({success:false,error:'Unable to save profile'});
    } finally { client.release(); }
  });

  // Row locking makes simultaneous photo changes safe; only the replaced asset is removed.
  const swapPhoto = async (userId, photo) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const previous = await client.query('SELECT avatar_public_id FROM users WHERE id=$1 FOR UPDATE',[userId]);
      if (!previous.rows.length) throw new Error('Account not found');
      const result = await client.query(`UPDATE users SET avatar_url=$1, avatar_public_id=$2 WHERE id=$3 RETURNING ${PROFILE_FIELDS}`,
        [photo?.secure_url || null, photo?.public_id || null,userId]);
      await client.query('COMMIT');
      return {user:result.rows[0],oldId:previous.rows[0].avatar_public_id};
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  };
  app.post('/api/profile/avatar', authenticateToken, (req, res) => {
    photoUpload(req, res, async (error) => {
      if (error) return res.status(400).json({success:false,error:error.code==='LIMIT_FILE_SIZE'?'Photo must be 5 MB or smaller':'Upload one JPG, PNG or WebP photo'});
      if (!req.file || !isImage(req.file.buffer)) return res.status(400).json({success:false,error:'Choose a valid JPG, PNG or WebP photo'});
      let photo;
      try {
        photo = await new Promise((resolve,reject) => {
          cloudinary.uploader.upload_stream({folder:'unilnk_profiles',resource_type:'image',
            transformation:[{width:1600,height:1600,crop:'limit',quality:'auto'}]},(err,result) => err?reject(err):resolve(result)).end(req.file.buffer);
        });
        const saved = await swapPhoto(req.user.id,photo);
        await cleanPhoto(saved.oldId);
        res.json({success:true,user:saved.user});
      } catch (err) {
        await cleanPhoto(photo?.public_id);
        console.error('Profile photo failed:',err.message);
        res.status(500).json({success:false,error:'Unable to save photo. Please try again'});
      }
    });
  });
  app.delete('/api/profile/avatar', authenticateToken, async (req,res) => {
    try {
      const saved = await swapPhoto(req.user.id,null);
      await cleanPhoto(saved.oldId);
      res.json({success:true,user:saved.user});
    } catch (error) { res.status(500).json({success:false,error:'Unable to remove photo'}); }
  });
  app.put('/api/profile/password', authenticateToken, async (req,res) => {
    const {current_password,new_password} = req.body || {};
    const error = validatePassword(new_password);
    if (typeof current_password !== 'string' || error) return res.status(400).json({success:false,error:error || 'Enter your current password'});
    try {
      const result = await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.user.id]);
      const hash = result.rows[0]?.password_hash;
      const valid = hash?.startsWith('$2') ? await bcrypt.compare(current_password,hash) : hash === current_password;
      if (!hash || !valid) return res.status(400).json({success:false,error:'Current password is incorrect'});
      if (current_password===new_password) return res.status(400).json({success:false,error:'Choose a different new password'});
      const newHash = await bcrypt.hash(new_password,12);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const changed = await client.query('UPDATE users SET password_hash=$1 WHERE id=$2 AND password_hash=$3 RETURNING id',[newHash,req.user.id,hash]);
        if (!changed.rows.length) {
          await client.query('ROLLBACK');
          return res.status(409).json({success:false,error:'Password changed elsewhere. Please try again'});
        }
        await client.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL',[req.user.id]);
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK'); throw error; }
      finally { client.release(); }
      res.json({success:true});
    } catch (error) { console.error('Password change failed:',error.message); res.status(500).json({success:false,error:'Unable to change password'}); }
  });
}
module.exports = { registerProfileRoutes, validateProfile, isImage };

