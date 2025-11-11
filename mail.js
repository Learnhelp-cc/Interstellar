import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mailDbPath = path.join(__dirname, 'mail.db');

let mailDb;

function addMissingColumns(tableName, expectedColumns) {
  const tableInfo = mailDb.prepare(`PRAGMA table_info(${tableName})`).all();
  const existingColumns = tableInfo.map(col => col.name);

  for (const col of expectedColumns) {
    if (!existingColumns.includes(col.name)) {
      try {
        mailDb.exec(`ALTER TABLE ${tableName} ADD COLUMN ${col.definition}`);
        console.log(`Added missing column ${col.name} to ${tableName}`);
      } catch (error) {
        console.error(`Failed to add column ${col.name} to ${tableName}:`, error);
      }
    }
  }
}

export function initMailDB() {
  mailDb = new Database(mailDbPath);

  // Create emails table
  mailDb.exec(`
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

  // Expected columns for emails table
  const emailsExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'user_id', definition: 'user_id INTEGER NOT NULL' },
    { name: 'to_email', definition: 'to_email TEXT NOT NULL' },
    { name: 'subject', definition: 'subject TEXT NOT NULL' },
    { name: 'body', definition: 'body TEXT NOT NULL' },
    { name: 'sent_at', definition: 'sent_at DATETIME DEFAULT CURRENT_TIMESTAMP' }
  ];

  addMissingColumns('emails', emailsExpectedColumns);

  // Create received_emails table
  mailDb.exec(`
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

  // Expected columns for received_emails table
  const receivedEmailsExpectedColumns = [
    { name: 'id', definition: 'id INTEGER PRIMARY KEY AUTOINCREMENT' },
    { name: 'recipient_username', definition: 'recipient_username TEXT NOT NULL' },
    { name: 'from_email', definition: 'from_email TEXT NOT NULL' },
    { name: 'to_email', definition: 'to_email TEXT NOT NULL' },
    { name: 'subject', definition: 'subject TEXT NOT NULL' },
    { name: 'body', definition: 'body TEXT NOT NULL' },
    { name: 'received_at', definition: 'received_at DATETIME DEFAULT CURRENT_TIMESTAMP' }
  ];

  addMissingColumns('received_emails', receivedEmailsExpectedColumns);

  return mailDb;
}

// Email functions
export function createEmail(userId, toEmail, subject, body) {
  const stmt = mailDb.prepare('INSERT INTO emails (user_id, to_email, subject, body) VALUES (?, ?, ?, ?)');
  return stmt.run(userId, toEmail, subject, body);
}

export function getEmails(userId, limit = 50) {
  const stmt = mailDb.prepare('SELECT * FROM emails WHERE user_id = ? ORDER BY sent_at DESC LIMIT ?');
  return stmt.all(userId, limit);
}

export function deleteEmail(userId, emailId) {
  const stmt = mailDb.prepare('DELETE FROM emails WHERE id = ? AND user_id = ?');
  return stmt.run(emailId, userId);
}

// Received email functions
export function createReceivedEmail(recipientUsername, fromEmail, toEmail, subject, body) {
  const stmt = mailDb.prepare('INSERT INTO received_emails (recipient_username, from_email, to_email, subject, body) VALUES (?, ?, ?, ?, ?)');
  return stmt.run(recipientUsername, fromEmail, toEmail, subject, body);
}

export function getReceivedEmails(username, limit = 50) {
  const stmt = mailDb.prepare('SELECT * FROM received_emails WHERE recipient_username = ? ORDER BY received_at DESC LIMIT ?');
  return stmt.all(username, limit);
}

export function deleteReceivedEmail(username, emailId) {
  const stmt = mailDb.prepare('DELETE FROM received_emails WHERE id = ? AND recipient_username = ?');
  return stmt.run(emailId, username);
}
