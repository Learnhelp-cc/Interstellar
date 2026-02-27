import Database from 'better-sqlite3';
import { promisify } from 'util';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import * as openpgp from 'openpgp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(process.cwd(), 'users.db');
const referDbPath = path.join(process.cwd(), 'referrals.db');
const aiDbPath = path.join(process.cwd(), 'ai.db');
const keysDbPath = path.join(process.cwd(), 'keys.db');
const musicDbPath = path.join(process.cwd(), 'music.db');

let db;
let referDb;
let aiDb;
let keysDb;
let musicDb;

export { db, referDb, aiDb, keysDb, musicDb };

export function initDB() {
  db = new Database(dbPath);

  // Create users table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      pending BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Add device_token column if it doesn't exist
  try {
    const tableInfo = db.prepare("PRAGMA table_info(users)").all();
    const hasDeviceToken = tableInfo.some(row => row.name === 'device_token');

    if (!hasDeviceToken) {
      db.prepare(`ALTER TABLE users ADD COLUMN device_token TEXT`).run();
      // Note: UNIQUE constraint added separately to avoid issues with existing NULL values
      db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_token ON users(device_token)`).run();
    }
  } catch (error) {
    console.error('Failed to add device_token column:', error);
  }

  // Create messages table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Create dismissals table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS dismissals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message_id INTEGER NOT NULL,
      dismissed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (message_id) REFERENCES messages (id),
      UNIQUE(user_id, message_id)
    )
  `).run();

  // Create search_history table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS search_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      title TEXT,
      visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `).run();

  // Create emails table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      to_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `).run();

  // Create received_emails table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS received_emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient_username TEXT NOT NULL,
      from_email TEXT NOT NULL,
      to_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      received_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Initialize AI database
  try {
    aiDb = new Database(aiDbPath);
    console.log('AI database initialized at:', aiDbPath);

    // Create ai_chats table
    aiDb.prepare(`
      CREATE TABLE IF NOT EXISTS ai_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    // Create ai_messages table
    aiDb.prepare(`
      CREATE TABLE IF NOT EXISTS ai_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        role TEXT NOT NULL, -- 'user' or 'assistant'
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    console.log('AI database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize AI database:', error);
  }

  // Initialize referral database
  try {
    referDb = new Database(referDbPath);
    console.log('Referral database initialized at:', referDbPath);

    // Create referral_codes table
    referDb.prepare(`
      CREATE TABLE IF NOT EXISTS referral_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    // Create referrals table
    referDb.prepare(`
      CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL,
        referred_user_id INTEGER NOT NULL,
        referral_code_used TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(referred_user_id)
      )
    `).run();

    // Create used_by table to track which users used which referral codes
    referDb.prepare(`
      CREATE TABLE IF NOT EXISTS used_by (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        referral_code TEXT NOT NULL,
        referrer_user_id INTEGER,
        referrer_username TEXT,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id)
      )
    `).run();

    console.log('Referral database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize referral database:', error);
    referDb = null; // Ensure it's null if initialization fails
  }

  // Initialize keys database for AES-128 encryption
  try {
    keysDb = new Database(keysDbPath);
    console.log('Keys database initialized at:', keysDbPath);

    // Create user_keys table for AES-128 keys
    keysDb.prepare(`
      CREATE TABLE IF NOT EXISTS user_keys (
        user_id INTEGER PRIMARY KEY,
        aes_key TEXT NOT NULL, -- Base64 encoded 16-byte AES key
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    console.log('Keys database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize keys database:', error);
    keysDb = null; // Ensure it's null if initialization fails
  }

  // Initialize music database
  try {
    musicDb = new Database(musicDbPath);
    console.log('Music database initialized at:', musicDbPath);

    // Create music_files table
    musicDb.prepare(`
      CREATE TABLE IF NOT EXISTS music_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        gpg_signature TEXT,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `).run();

    // Create music_queues table for user queues
    musicDb.prepare(`
      CREATE TABLE IF NOT EXISTS music_queues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        music_file_id INTEGER NOT NULL,
        position INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (music_file_id) REFERENCES music_files (id),
        UNIQUE(user_id, music_file_id)
      )
    `).run();

    // Create user_gpg_keys table
    musicDb.prepare(`
      CREATE TABLE IF NOT EXISTS user_gpg_keys (
        user_id INTEGER PRIMARY KEY,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        key_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `).run();

    console.log('Music database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize music database:', error);
    musicDb = null; // Ensure it's null if initialization fails
  }

  return db;
}

export function getUser(username) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  return stmt.get(username);
}

export function createUser(username, password) {
  const stmt = db.prepare('INSERT INTO users (username, password, pending) VALUES (?, ?, TRUE)');
  const result = stmt.run(username, password);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function updateUser(id, updates) {
  const updatesArray = [];
  const values = [];
  
  if (updates.username !== undefined) {
    updatesArray.push('username = ?');
    values.push(updates.username);
  }

  if (updates.password !== undefined) {
    updatesArray.push('password = ?');
    values.push(updates.password);
  }

  if (updates.pending !== undefined) {
    updatesArray.push('pending = ?');
    values.push(typeof updates.pending === 'boolean' ? (updates.pending ? 1 : 0) : updates.pending);
  }

  if (updatesArray.length > 0) {
    values.push(id);
    const query = `UPDATE users SET ${updatesArray.join(', ')} WHERE id = ?`;
    const stmt = db.prepare(query);
    const result = stmt.run(...values);
    return { changes: result.changes };
  } else {
    return { changes: 0 };
  }
}

export function getAllUsers() {
  const usersStmt = db.prepare('SELECT id, username, pending, created_at FROM users ORDER BY created_at DESC');
  const users = usersStmt.all();

  // Add referral information to each user
  const usersWithReferrals = [];
  for (const user of users) {
    try {
      const referralInfo = getUserReferralInfo(user.id);
      usersWithReferrals.push({
        ...user,
        referral_code_used: referralInfo?.referral_code || null,
        referrer_user_id: referralInfo?.referrer_user_id || null,
        referrer_username: referralInfo?.referrer_username || null,
        referral_used_at: referralInfo?.used_at || null
      });
    } catch (error) {
      usersWithReferrals.push({
        ...user,
        referral_code_used: null,
        referrer_user_id: null,
        referrer_username: null,
        referral_used_at: null
      });
    }
  }
  
  return usersWithReferrals;
}

export function deleteUser(id) {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');
  const result = stmt.run(id);
  return { changes: result.changes };
}

export function getUserByDeviceToken(token) {
  const stmt = db.prepare('SELECT * FROM users WHERE device_token = ?');
  return stmt.get(token);
}

export function updateDeviceToken(id, token) {
  const stmt = db.prepare('UPDATE users SET device_token = ? WHERE id = ?');
  const result = stmt.run(token, id);
  return { changes: result.changes };
}

// Referral functions
export function generateReferralCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

export function setUserReferralCode(userId) {
  if (!referDb) {
    throw new Error('Referral database not initialized');
  }

  let code;
  let attempts = 0;
  let existing;
  do {
    code = generateReferralCode();
    attempts++;
    if (attempts > 10) {
      throw new Error('Failed to generate unique referral code');
    }
    // Check if code already exists in referral_codes table
    const checkStmt = referDb.prepare('SELECT id FROM referral_codes WHERE code = ?');
    existing = checkStmt.get(code);
  } while (existing);

  const stmt = referDb.prepare('INSERT INTO referral_codes (user_id, code) VALUES (?, ?)');
  stmt.run(userId, code);
  return code;
}

export function getUserByReferralCode(code) {
  if (!referDb) {
    throw new Error('Referral database not initialized');
  }

  // First get the user_id from referral_codes table
  const referralStmt = referDb.prepare('SELECT user_id FROM referral_codes WHERE code = ?');
  const referralResult = referralStmt.get(code);

  if (!referralResult) {
    return null;
  }

  // Then get the user data from the main users table
  const userStmt = db.prepare('SELECT * FROM users WHERE id = ?');
  const user = userStmt.get(referralResult.user_id);

  if (user) {
    user.referral_code = code;
  }

  return user;
}

export function getUserReferrals(userId) {
  if (!referDb) {
    throw new Error('Referral database not initialized');
  }

  // First get the referral data
  const referralStmt = referDb.prepare(`
    SELECT referred_user_id, referral_code_used, created_at
    FROM referrals
    WHERE referrer_id = ?
    ORDER BY created_at DESC
  `);
  const referrals = referralStmt.all(userId);

  // Then get user data for each referral
  const result = [];
  for (const referral of referrals) {
    const userStmt = db.prepare('SELECT id, username, created_at FROM users WHERE id = ?');
    const user = userStmt.get(referral.referred_user_id);
    if (user) {
      result.push({
        id: user.id,
        username: user.username,
        created_at: user.created_at,
        referral_code_used: referral.referral_code_used
      });
    }
  }

  return result;
}

export function getUserReferralInfo(userId) {
  if (!referDb) {
    return null;
  }

  const stmt = referDb.prepare('SELECT referral_code, referrer_user_id, referrer_username, used_at FROM used_by WHERE user_id = ?');
  return stmt.get(userId);
}

export function createUserWithReferral(username, password, referralCode = null) {
  // First create the user
  const stmt = db.prepare(
    'INSERT INTO users (username, password, pending) VALUES (?, ?, TRUE)'
  );
  const result = stmt.run(username, password);
  const userId = result.lastInsertRowid;

  // Handle referral if provided
  if (referralCode && referDb) {
    const referrer = getUserByReferralCode(referralCode);
    if (referrer) {
      const referralStmt = referDb.prepare(
        'INSERT INTO referrals (referrer_id, referred_user_id, referral_code_used) VALUES (?, ?, ?)'
      );
      referralStmt.run(referrer.id, userId, referralCode);

      // Also track in used_by table
      const usedByStmt = referDb.prepare(
        'INSERT INTO used_by (user_id, referral_code, referrer_user_id, referrer_username) VALUES (?, ?, ?, ?)'
      );
      usedByStmt.run(userId, referralCode, referrer.id, referrer.username);
    }
  }

  return userId;
}

// Message functions
export function createMessage(message) {
  const stmt = db.prepare('INSERT INTO messages (message) VALUES (?)');
  const result = stmt.run(message);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getActiveMessages() {
  const stmt = db.prepare('SELECT * FROM messages WHERE active = 1 ORDER BY created_at DESC');
  return stmt.all();
}

export function getAllMessages() {
  const stmt = db.prepare('SELECT * FROM messages ORDER BY created_at DESC');
  return stmt.all();
}

export function updateMessage(id, updates) {
  const updatesArray = [];
  const values = [];
  
  if (updates.message !== undefined) {
    updatesArray.push('message = ?');
    values.push(updates.message);
  }

  if (updates.active !== undefined) {
    updatesArray.push('active = ?');
    values.push(updates.active ? 1 : 0);
  }

  if (updatesArray.length > 0) {
    values.push(id);
    const query = `UPDATE messages SET ${updatesArray.join(', ')} WHERE id = ?`;
    const stmt = db.prepare(query);
    const result = stmt.run(...values);
    return { changes: result.changes };
  } else {
    return { changes: 0 };
  }
}

export function deleteMessage(id) {
  const stmt = db.prepare('DELETE FROM messages WHERE id = ?');
  const result = stmt.run(id);
  return { changes: result.changes };
}

// Dismissal functions
export function dismissMessage(userId, messageId) {
  const stmt = db.prepare('INSERT OR IGNORE INTO dismissals (user_id, message_id) VALUES (?, ?)');
  const result = stmt.run(userId, messageId);
  return { changes: result.changes };
}

export function getDismissedMessages(userId) {
  const stmt = db.prepare('SELECT message_id FROM dismissals WHERE user_id = ?');
  const rows = stmt.all(userId);
  return rows.map(row => row.message_id);
}

export function getUndismissedMessages(userId) {
  const dismissed = getDismissedMessages(userId);
  const activeMessages = getActiveMessages();
  return activeMessages.filter(msg => !dismissed.includes(msg.id));
}

// Search history functions
export function addSearchHistory(userId, url, title = null) {
  const stmt = db.prepare('INSERT INTO search_history (user_id, url, title) VALUES (?, ?, ?)');
  const result = stmt.run(userId, url, title);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getSearchHistory(userId, limit = 50) {
  const stmt = db.prepare('SELECT * FROM search_history WHERE user_id = ? ORDER BY visited_at DESC LIMIT ?');
  return stmt.all(userId, limit);
}

export function deleteSearchHistory(userId, historyId) {
  const stmt = db.prepare('DELETE FROM search_history WHERE id = ? AND user_id = ?');
  const result = stmt.run(historyId, userId);
  return { changes: result.changes };
}

export function clearSearchHistory(userId) {
  const stmt = db.prepare('DELETE FROM search_history WHERE user_id = ?');
  const result = stmt.run(userId);
  return { changes: result.changes };
}

// Email functions
export function createEmail(userId, toEmail, subject, body) {
  const stmt = db.prepare('INSERT INTO emails (user_id, to_email, subject, body) VALUES (?, ?, ?, ?)');
  const result = stmt.run(userId, toEmail, subject, body);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getEmails(userId, limit = 50) {
  const stmt = db.prepare('SELECT * FROM emails WHERE user_id = ? ORDER BY sent_at DESC LIMIT ?');
  return stmt.all(userId, limit);
}

export function deleteEmail(userId, emailId) {
  const stmt = db.prepare('DELETE FROM emails WHERE id = ? AND user_id = ?');
  const result = stmt.run(emailId, userId);
  return { changes: result.changes };
}

// Received email functions
export function createReceivedEmail(recipientUsername, fromEmail, toEmail, subject, body) {
  const stmt = db.prepare('INSERT INTO received_emails (recipient_username, from_email, to_email, subject, body) VALUES (?, ?, ?, ?, ?)');
  const result = stmt.run(recipientUsername, fromEmail, toEmail, subject, body);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getReceivedEmails(username, limit = 50) {
  const stmt = db.prepare('SELECT * FROM received_emails WHERE recipient_username = ? ORDER BY received_at DESC LIMIT ?');
  return stmt.all(username, limit);
}

export function deleteReceivedEmail(username, emailId) {
  const stmt = db.prepare('DELETE FROM received_emails WHERE id = ? AND recipient_username = ?');
  const result = stmt.run(emailId, username);
  return { changes: result.changes };
}

// AI Chat functions
export function createAIChat(userId, title = null) {
  const stmt = aiDb.prepare('INSERT INTO ai_chats (user_id, title) VALUES (?, ?)');
  const result = stmt.run(userId, title);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getAIChats(userId) {
  const stmt = aiDb.prepare('SELECT * FROM ai_chats WHERE user_id = ? ORDER BY updated_at DESC');
  return stmt.all(userId);
}

export function getAIChat(chatId, userId) {
  const stmt = aiDb.prepare('SELECT * FROM ai_chats WHERE id = ? AND user_id = ?');
  return stmt.get(chatId, userId);
}

export function updateAIChatTitle(chatId, userId, title) {
  const stmt = aiDb.prepare('UPDATE ai_chats SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?');
  const result = stmt.run(title, chatId, userId);
  return { changes: result.changes };
}

export function deleteAIChat(chatId, userId) {
  const stmt = aiDb.prepare('DELETE FROM ai_chats WHERE id = ? AND user_id = ?');
  const result = stmt.run(chatId, userId);
  return { changes: result.changes };
}

export function addAIMessage(chatId, role, content) {
  const stmt = aiDb.prepare('INSERT INTO ai_messages (chat_id, role, content) VALUES (?, ?, ?)');
  const result = stmt.run(chatId, role, content);
  
  // Update chat updated_at
  const updateStmt = aiDb.prepare('UPDATE ai_chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  updateStmt.run(chatId);
  
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getAIMessages(chatId) {
  const stmt = aiDb.prepare('SELECT * FROM ai_messages WHERE chat_id = ? ORDER BY created_at ASC');
  return stmt.all(chatId);
}

// GPG functions
export function getUserGPGKey(userId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('SELECT * FROM user_gpg_keys WHERE user_id = ?');
  return stmt.get(userId);
}

export function createUserGPGKey(userId, publicKey, privateKey, keyId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('INSERT INTO user_gpg_keys (user_id, public_key, private_key, key_id) VALUES (?, ?, ?, ?)');
  stmt.run(userId, publicKey, privateKey, keyId);
  return { publicKey, privateKey, keyId };
}

export async function ensureUserGPGKey(userId) {
  let keyData = getUserGPGKey(userId);
  if (!keyData) {
    // Generate new GPG key pair using OpenPGP
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'ecc',
      curve: 'curve25519',
      userIDs: [{ name: `User ${userId}`, email: `user${userId}@interstellar.local` }],
      passphrase: '', // No passphrase for simplicity
    });

    const keyId = privateKey.getKeyID().toHex();

    // Store in database
    createUserGPGKey(userId, publicKey.armor(), privateKey.armor(), keyId);

    keyData = { publicKey: publicKey.armor(), privateKey: privateKey.armor(), keyId };
  }
  return keyData;
}

// Music functions
export function addMusicFile(userId, filename, filepath, fileHash, gpgSignature = null) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('INSERT INTO music_files (user_id, filename, filepath, file_hash, gpg_signature) VALUES (?, ?, ?, ?, ?)');
  const result = stmt.run(userId, filename, filepath, fileHash, gpgSignature);
  return { lastInsertRowid: result.lastInsertRowid };
}

export function getMusicFiles(userId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('SELECT * FROM music_files WHERE user_id = ? ORDER BY uploaded_at DESC');
  return stmt.all(userId);
}

export function getMusicFileByHash(userId, fileHash) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('SELECT * FROM music_files WHERE user_id = ? AND file_hash = ?');
  return stmt.get(userId, fileHash);
}

export function deleteMusicFile(userId, fileId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('DELETE FROM music_files WHERE id = ? AND user_id = ?');
  const result = stmt.run(fileId, userId);
  return { changes: result.changes };
}

export function addToQueue(userId, musicFileId, position = null) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  // If no position specified, add to end
  if (position === null) {
    const countStmt = musicDb.prepare('SELECT COUNT(*) as count FROM music_queues WHERE user_id = ?');
    const row = countStmt.get(userId);
    position = row.count;
  }
  
  const stmt = musicDb.prepare('INSERT OR REPLACE INTO music_queues (user_id, music_file_id, position) VALUES (?, ?, ?)');
  const result = stmt.run(userId, musicFileId, position);
  return { changes: result.changes };
}

export function getMusicQueue(userId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare(`
    SELECT mq.*, mf.filename, mf.filepath
    FROM music_queues mq
    JOIN music_files mf ON mq.music_file_id = mf.id
    WHERE mq.user_id = ?
    ORDER BY mq.position ASC
  `);
  return stmt.all(userId);
}

export function removeFromQueue(userId, musicFileId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('DELETE FROM music_queues WHERE user_id = ? AND music_file_id = ?');
  const result = stmt.run(userId, musicFileId);
  return { changes: result.changes };
}

export function clearMusicQueue(userId) {
  if (!musicDb) {
    throw new Error('Music database not initialized');
  }
  const stmt = musicDb.prepare('DELETE FROM music_queues WHERE user_id = ?');
  const result = stmt.run(userId);
  return { changes: result.changes };
}

// AES-128 Encryption functions
export function getUserAESKey(userId) {
  if (!keysDb) {
    throw new Error('Keys database not initialized');
  }
  const stmt = keysDb.prepare('SELECT aes_key FROM user_keys WHERE user_id = ?');
  const row = stmt.get(userId);
  return row ? row.aes_key : null;
}

export function createUserAESKey(userId) {
  if (!keysDb) {
    throw new Error('Keys database not initialized');
  }
  // Generate a random 16-byte (128-bit) key
  const key = crypto.randomBytes(16);
  const keyBase64 = key.toString('base64');

  const stmt = keysDb.prepare('INSERT OR REPLACE INTO user_keys (user_id, aes_key) VALUES (?, ?)');
  stmt.run(userId, keyBase64);
  return keyBase64;
}

export function ensureUserAESKey(userId) {
  let key = getUserAESKey(userId);
  if (!key) {
    key = createUserAESKey(userId);
  }
  return key;
}

export function encryptAES128(text, keyBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = crypto.randomBytes(16); // AES block size
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted data as base64
  const combined = Buffer.concat([iv, Buffer.from(encrypted, 'hex')]);
  return combined.toString('base64');
}

export function decryptAES128(encryptedBase64, keyBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const combined = Buffer.from(encryptedBase64, 'base64');

  const iv = combined.slice(0, 16);
  const encrypted = combined.slice(16);

  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Warnlist functions
export function createWarnlistTable() {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  db.prepare(`
    CREATE TABLE IF NOT EXISTS warnlist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT UNIQUE NOT NULL,
      warning_message TEXT,
      active BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

export function addDomainToWarnlist(domain, warningMessage = null) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const stmt = db.prepare('INSERT INTO warnlist (domain, warning_message) VALUES (?, ?)');
  try {
    const result = stmt.run(domain.toLowerCase(), warningMessage);
    return { lastInsertRowid: result.lastInsertRowid };
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new Error('Domain already exists in warnlist');
    } else {
      throw err;
    }
  }
}

export function getWarnlist() {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const stmt = db.prepare('SELECT * FROM warnlist ORDER BY created_at DESC');
  return stmt.all();
}

export function getActiveWarnlist() {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const stmt = db.prepare('SELECT * FROM warnlist WHERE active = 1 ORDER BY created_at DESC');
  return stmt.all();
}

export function getDomainFromWarnlist(domain) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const stmt = db.prepare('SELECT * FROM warnlist WHERE domain = ?');
  return stmt.get(domain.toLowerCase());
}

export function updateDomainInWarnlist(id, updates) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const updatesArray = [];
  const values = [];
  
  if (updates.warning_message !== undefined) {
    updatesArray.push('warning_message = ?');
    values.push(updates.warning_message);
  }
  
  if (updates.active !== undefined) {
    updatesArray.push('active = ?');
    values.push(updates.active ? 1 : 0);
  }
  
  if (updatesArray.length > 0) {
    values.push(id);
    const query = `UPDATE warnlist SET ${updatesArray.join(', ')} WHERE id = ?`;
    const stmt = db.prepare(query);
    const result = stmt.run(...values);
    return { changes: result.changes };
  } else {
    return { changes: 0 };
  }
}

export function deleteDomainFromWarnlist(id) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  const stmt = db.prepare('DELETE FROM warnlist WHERE id = ?');
  const result = stmt.run(id);
  return { changes: result.changes };
}

export function bulkUpdateWarnlist(action, domainIds) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  let query = '';
  if (action === 'activate') {
    query = 'UPDATE warnlist SET active = 1 WHERE id IN (';
  } else if (action === 'deactivate') {
    query = 'UPDATE warnlist SET active = 0 WHERE id IN (';
  } else if (action === 'delete') {
    query = 'DELETE FROM warnlist WHERE id IN (';
  } else {
    throw new Error('Invalid bulk action');
  }
  
  const placeholders = domainIds.map(() => '?').join(',');
  query += placeholders + ')';
  
  const stmt = db.prepare(query);
  const result = stmt.run(...domainIds);
  return { changes: result.changes };
}

export function importWarnlist(domains) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  let addedCount = 0;
  
  if (domains.length === 0) {
    return 0;
  }
  
  const stmt = db.prepare('INSERT OR IGNORE INTO warnlist (domain, warning_message) VALUES (?, ?)');
  
  for (const domain of domains) {
    if (domain.domain) {
      const result = stmt.run(domain.domain.toLowerCase(), domain.warning_message || null);
      if (result.changes > 0) {
        addedCount++;
      }
    }
  }
  
  return addedCount;
}

export function isDomainWarned(domain) {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  // Check exact domain match
  const exactStmt = db.prepare('SELECT warning_message FROM warnlist WHERE domain = ? AND active = 1');
  const result = exactStmt.get(domain.toLowerCase());
  
  if (result) {
    return {
      isWarned: true,
      warningMessage: result.warning_message || 'This website is flagged by the Webmaster! Visiting this is not confirmed to be safe!'
    };
  }
  
  // Check subdomain matches (e.g., if example.com is blocked, block sub.example.com)
  const domainParts = domain.toLowerCase().split('.');
  
  for (let i = 0; i < domainParts.length - 1; i++) {
    const subdomain = domainParts.slice(i).join('.');
    const subStmt = db.prepare('SELECT warning_message FROM warnlist WHERE domain = ? AND active = 1');
    const subResult = subStmt.get(subdomain);
    
    if (subResult) {
      return {
        isWarned: true,
        warningMessage: subResult.warning_message || 'This website is flagged by the Webmaster! Visiting this is not confirmed to be safe!'
      };
    }
  }
  
  return { isWarned: false };
}
