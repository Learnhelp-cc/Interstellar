import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'users.db');
const aiDbPath = path.join(__dirname, 'ai.db');
const keysDbPath = path.join(__dirname, 'keys.db');

let db;
let aiDb;
let keysDb;

export function initDB() {
  db = new Database(dbPath);

  // Create users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      pending BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add device_token column if it doesn't exist
  const tableInfo = db.prepare("PRAGMA table_info(users)").all();
  const hasDeviceToken = tableInfo.some(column => column.name === 'device_token');

  if (!hasDeviceToken) {
    try {
      db.exec(`ALTER TABLE users ADD COLUMN device_token TEXT`);
      // Note: UNIQUE constraint added separately to avoid issues with existing NULL values
      db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_token ON users(device_token)`);
    } catch (error) {
      console.error('Failed to add device_token column:', error);
    }
  }

  // Create messages table
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create dismissals table
  db.exec(`
    CREATE TABLE IF NOT EXISTS dismissals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message_id INTEGER NOT NULL,
      dismissed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (message_id) REFERENCES messages (id),
      UNIQUE(user_id, message_id)
    )
  `);

  // Create search_history table
  db.exec(`
    CREATE TABLE IF NOT EXISTS search_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      title TEXT,
      visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Create emails table
  db.exec(`
    CREATE TABLE IF NOT EXISTS emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      to_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Create received_emails table
  db.exec(`
    CREATE TABLE IF NOT EXISTS received_emails (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient_username TEXT NOT NULL,
      from_email TEXT NOT NULL,
      to_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      received_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Initialize AI database
  try {
    aiDb = new Database(aiDbPath);
    console.log('AI database initialized at:', aiDbPath);

    // Create ai_chats table
    aiDb.exec(`
      CREATE TABLE IF NOT EXISTS ai_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create ai_messages table
    aiDb.exec(`
      CREATE TABLE IF NOT EXISTS ai_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        role TEXT NOT NULL, -- 'user' or 'assistant'
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('AI database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize AI database:', error);
  }

  // Initialize keys database for AES-128 encryption
  try {
    keysDb = new Database(keysDbPath);
    console.log('Keys database initialized at:', keysDbPath);

    // Create user_keys table for AES-128 keys
    keysDb.exec(`
      CREATE TABLE IF NOT EXISTS user_keys (
        user_id INTEGER PRIMARY KEY,
        aes_key TEXT NOT NULL, -- Base64 encoded 16-byte AES key
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Keys database tables created successfully');
  } catch (error) {
    console.error('Failed to initialize keys database:', error);
    keysDb = null; // Ensure it's null if initialization fails
  }

  return db;
}

export function getUser(username) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  return stmt.get(username);
}

export function createUser(username, password) {
  const stmt = db.prepare(
    'INSERT INTO users (username, password, pending) VALUES (?, ?, TRUE)'
  );
  return stmt.run(username, password);
}

export function updateUser(id, updates) {
  if (updates.username !== undefined) {
    const stmt = db.prepare('UPDATE users SET username = ? WHERE id = ?');
    stmt.run(updates.username, id);
  }

  if (updates.password !== undefined) {
    const stmt = db.prepare('UPDATE users SET password = ? WHERE id = ?');
    stmt.run(updates.password, id);
  }

  if (updates.pending !== undefined) {
    const stmt = db.prepare('UPDATE users SET pending = ? WHERE id = ?');
    stmt.run(typeof updates.pending === 'boolean' ? (updates.pending ? 1 : 0) : updates.pending, id);
  }

  return { changes: 1 }; // Return a dummy result
}

export function getAllUsers() {
  const stmt = db.prepare('SELECT id, username, pending, created_at FROM users ORDER BY created_at DESC');
  return stmt.all();
}

export function deleteUser(id) {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');
  return stmt.run(id);
}

export function getUserByDeviceToken(token) {
  const stmt = db.prepare('SELECT * FROM users WHERE device_token = ?');
  return stmt.get(token);
}

export function updateDeviceToken(id, token) {
  const stmt = db.prepare('UPDATE users SET device_token = ? WHERE id = ?');
  return stmt.run(token, id);
}

// Message functions
export function createMessage(message) {
  const stmt = db.prepare('INSERT INTO messages (message) VALUES (?)');
  return stmt.run(message);
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
  if (updates.message !== undefined) {
    const stmt = db.prepare('UPDATE messages SET message = ? WHERE id = ?');
    stmt.run(updates.message, id);
  }
  if (updates.active !== undefined) {
    const stmt = db.prepare('UPDATE messages SET active = ? WHERE id = ?');
    stmt.run(updates.active ? 1 : 0, id);
  }
  return { changes: 1 };
}

export function deleteMessage(id) {
  const stmt = db.prepare('DELETE FROM messages WHERE id = ?');
  return stmt.run(id);
}

// Dismissal functions
export function dismissMessage(userId, messageId) {
  const stmt = db.prepare('INSERT OR IGNORE INTO dismissals (user_id, message_id) VALUES (?, ?)');
  return stmt.run(userId, messageId);
}

export function getDismissedMessages(userId) {
  const stmt = db.prepare('SELECT message_id FROM dismissals WHERE user_id = ?');
  return stmt.all().map(row => row.message_id);
}

export function getUndismissedMessages(userId) {
  const dismissed = getDismissedMessages(userId);
  const activeMessages = getActiveMessages();
  return activeMessages.filter(msg => !dismissed.includes(msg.id));
}

// Search history functions
export function addSearchHistory(userId, url, title = null) {
  const stmt = db.prepare('INSERT INTO search_history (user_id, url, title) VALUES (?, ?, ?)');
  return stmt.run(userId, url, title);
}

export function getSearchHistory(userId, limit = 50) {
  const stmt = db.prepare('SELECT * FROM search_history WHERE user_id = ? ORDER BY visited_at DESC LIMIT ?');
  return stmt.all(userId, limit);
}

export function deleteSearchHistory(userId, historyId) {
  const stmt = db.prepare('DELETE FROM search_history WHERE id = ? AND user_id = ?');
  return stmt.run(historyId, userId);
}

export function clearSearchHistory(userId) {
  const stmt = db.prepare('DELETE FROM search_history WHERE user_id = ?');
  return stmt.run(userId);
}

// Email functions
export function createEmail(userId, toEmail, subject, body) {
  const stmt = db.prepare('INSERT INTO emails (user_id, to_email, subject, body) VALUES (?, ?, ?, ?)');
  return stmt.run(userId, toEmail, subject, body);
}

export function getEmails(userId, limit = 50) {
  const stmt = db.prepare('SELECT * FROM emails WHERE user_id = ? ORDER BY sent_at DESC LIMIT ?');
  return stmt.all(userId, limit);
}

export function deleteEmail(userId, emailId) {
  const stmt = db.prepare('DELETE FROM emails WHERE id = ? AND user_id = ?');
  return stmt.run(emailId, userId);
}

// Received email functions
export function createReceivedEmail(recipientUsername, fromEmail, toEmail, subject, body) {
  const stmt = db.prepare('INSERT INTO received_emails (recipient_username, from_email, to_email, subject, body) VALUES (?, ?, ?, ?, ?)');
  return stmt.run(recipientUsername, fromEmail, toEmail, subject, body);
}

export function getReceivedEmails(username, limit = 50) {
  const stmt = db.prepare('SELECT * FROM received_emails WHERE recipient_username = ? ORDER BY received_at DESC LIMIT ?');
  return stmt.all(username, limit);
}

export function deleteReceivedEmail(username, emailId) {
  const stmt = db.prepare('DELETE FROM received_emails WHERE id = ? AND recipient_username = ?');
  return stmt.run(emailId, username);
}

// AI Chat functions
export function createAIChat(userId, title = null) {
  const stmt = aiDb.prepare('INSERT INTO ai_chats (user_id, title) VALUES (?, ?)');
  const result = stmt.run(userId, title);
  return result.lastInsertRowid;
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
  return stmt.run(title, chatId, userId);
}

export function deleteAIChat(chatId, userId) {
  const stmt = aiDb.prepare('DELETE FROM ai_chats WHERE id = ? AND user_id = ?');
  return stmt.run(chatId, userId);
}

export function addAIMessage(chatId, role, content) {
  const stmt = aiDb.prepare('INSERT INTO ai_messages (chat_id, role, content) VALUES (?, ?, ?)');
  const result = stmt.run(chatId, role, content);
  // Update chat updated_at
  aiDb.prepare('UPDATE ai_chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(chatId);
  return result.lastInsertRowid;
}

export function getAIMessages(chatId) {
  const stmt = aiDb.prepare('SELECT * FROM ai_messages WHERE chat_id = ? ORDER BY created_at ASC');
  return stmt.all(chatId);
}

// AES-128 Encryption functions
export function getUserAESKey(userId) {
  if (!keysDb) {
    throw new Error('Keys database not initialized');
  }
  const stmt = keysDb.prepare('SELECT aes_key FROM user_keys WHERE user_id = ?');
  const result = stmt.get(userId);
  return result ? result.aes_key : null;
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
