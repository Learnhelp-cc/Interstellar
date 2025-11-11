import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'users.db');

let db;

function addMissingColumns(tableName, expectedColumns) {
  const tableInfo = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const existingColumns = tableInfo.map(col => col.name);

  for (const col of expectedColumns) {
    if (!existingColumns.includes(col.name)) {
      try {
        db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${col.definition}`);
        console.log(`Added missing column ${col.name} to ${tableName}`);
      } catch (error) {
        console.error(`Failed to add column ${col.name} to ${tableName}:`, error);
      }
    }
  }
}

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

  // Expected columns for users table
  const usersExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'username', definition: 'username TEXT UNIQUE NOT NULL' },
    { name: 'password', definition: 'password TEXT NOT NULL' },
    { name: 'pending', definition: 'pending BOOLEAN DEFAULT TRUE' },
    { name: 'created_at', definition: 'created_at DATETIME DEFAULT CURRENT_TIMESTAMP' },
    { name: 'device_token', definition: 'device_token TEXT' }
  ];

  addMissingColumns('users', usersExpectedColumns);

  // Add unique index for device_token if not exists
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_device_token ON users(device_token)`);

  // Create messages table
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Expected columns for messages table
  const messagesExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'message', definition: 'message TEXT NOT NULL' },
    { name: 'active', definition: 'active BOOLEAN DEFAULT TRUE' },
    { name: 'created_at', definition: 'created_at DATETIME DEFAULT CURRENT_TIMESTAMP' }
  ];

  addMissingColumns('messages', messagesExpectedColumns);

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

  // Expected columns for dismissals table
  const dismissalsExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'user_id', definition: 'user_id INTEGER NOT NULL' },
    { name: 'message_id', definition: 'message_id INTEGER NOT NULL' },
    { name: 'dismissed_at', definition: 'dismissed_at DATETIME DEFAULT CURRENT_TIMESTAMP' }
  ];

  addMissingColumns('dismissals', dismissalsExpectedColumns);

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

  // Expected columns for search_history table
  const searchHistoryExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'user_id', definition: 'user_id INTEGER NOT NULL' },
    { name: 'url', definition: 'url TEXT NOT NULL' },
    { name: 'title', definition: 'title TEXT' },
    { name: 'visited_at', definition: 'visited_at DATETIME DEFAULT CURRENT_TIMESTAMP' }
  ];

  addMissingColumns('search_history', searchHistoryExpectedColumns);



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
