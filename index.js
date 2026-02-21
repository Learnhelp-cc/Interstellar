import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { createBareServer } from "@nebula-services/bare-server-node";
import chalk from "chalk";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import basicAuth from "express-basic-auth";
import mime from "mime";
import fetch from "node-fetch";
import dotenv from "dotenv";
import { WebSocketServer } from "ws";
import { Client } from "ssh2";
import crypto from "crypto";
import { execSync } from "child_process";
import Database from 'better-sqlite3';
import multer from 'multer';
import * as openpgp from 'openpgp';
// import { setupMasqr } from "./Masqr.js";
import config from "./config.js";
import { initDB, getUser, createUser, updateUser, getAllUsers, deleteUser, getUserByDeviceToken, updateDeviceToken, createMessage, getActiveMessages, getAllMessages, updateMessage, deleteMessage, dismissMessage, getUndismissedMessages, addSearchHistory, getSearchHistory, deleteSearchHistory, clearSearchHistory, createAIChat, getAIChats, getAIChat, deleteAIChat, addAIMessage, getAIMessages, ensureUserAESKey, encryptAES128, decryptAES128, generateReferralCode, setUserReferralCode, getUserByReferralCode, getUserReferrals, createUserWithReferral, referDb, addMusicFile, getMusicFiles, getMusicFileByHash, deleteMusicFile, addToQueue, getMusicQueue, removeFromQueue, clearMusicQueue, ensureUserGPGKey, createWarnlistTable } from "./db.js";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = path.dirname(new URL(import.meta.url).pathname);
dotenv.config({ path: path.join(process.cwd(), "creds.env") });

// AES-256 encryption setup
const MASTER_KEY = process.env.MASTER_KEY;
if (!MASTER_KEY) {
  console.error('MASTER_KEY environment variable is required');
  process.exit(1);
}
const SALT = "fixedsaltforencryption123"; // Fixed salt for key derivation
const AES_KEY = crypto.pbkdf2Sync(MASTER_KEY, SALT, 100000, 32, 'sha256'); // Derive 32-byte key

function encryptPassword(password) {
  const iv = crypto.randomBytes(16); // 16 bytes for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  // Store IV + authTag + encrypted
  return Buffer.concat([iv, authTag, Buffer.from(encrypted, 'hex')]).toString('base64');
}

function decryptPassword(encryptedPassword) {
  const data = Buffer.from(encryptedPassword, 'base64');
  const iv = data.slice(0, 16);
  const authTag = data.slice(16, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Configure multer for file uploads
const upload = multer({
  dest: path.join(process.cwd(), 'uploads'),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow images only
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Configure multer for music file uploads
const musicUpload = multer({
  dest: path.join(process.cwd(), 'static/assets/custommusic'),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit for music files
  },
  fileFilter: (req, file, cb) => {
    // Allow audio files only
    if (file.mimetype.startsWith('audio/') || file.originalname.toLowerCase().endsWith('.mp3')) {
      cb(null, true);
    } else {
      cb(new Error('Only audio files are allowed'));
    }
  }
});

// Ensure uploads directory exists
const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Ensure custom music directory exists
const customMusicDir = path.join(process.cwd(), 'static/assets/custommusic');
if (!fs.existsSync(customMusicDir)) {
  fs.mkdirSync(customMusicDir, { recursive: true });
}

// Initialize database
initDB();
console.log(chalk.green("📊 Database initialized"));

// Initialize warnlist table
try {
  createWarnlistTable();
  console.log(chalk.green("🛡️ Warnlist table initialized"));
} catch (error) {
  console.error(chalk.red("Failed to initialize warnlist table:"), error);
}

// Migrate existing plain text passwords to encrypted
const migrationDb = new Database(path.join(process.cwd(), 'users.db'));
const users = migrationDb.prepare('SELECT id, password FROM users').all();

for (const user of users) {
  try {
    // Try to decrypt - if it fails, it's plain text
    decryptPassword(user.password);
  } catch (error) {
    // It's plain text, encrypt it
    const encrypted = encryptPassword(user.password);
    migrationDb.prepare('UPDATE users SET password = ? WHERE id = ?').run(encrypted, user.id);
    console.log(chalk.yellow(`🔐 Migrated password for user ID ${user.id} to encrypted format`));
  }
}

const server = http.createServer();
const app = express();

// Session store for user authentication
const sessions = new Map();

// Cookie jar for session persistence
const cookieJar = new Map();

// Request throttling - track requests per domain
const requestTracker = new Map();
const THROTTLE_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30; // Max requests per domain per minute

// Custom HTTP Agent with browser-like headers and throttling
class CloudflareFriendlyHttpAgent extends http.Agent {
  constructor(options = {}) {
    super({
      keepAlive: true,
      maxSockets: 10,
      maxFreeSockets: 5,
      timeout: 30000,
      ...options
    });
  }

  createConnection(options, callback) {
    // Add throttling check
    const domain = options.host || options.hostname;
    const now = Date.now();
    const domainKey = `${domain}`;

    // Higher limits for Discord domains
    const isDiscord = domain.includes('discord.com') || domain.includes('discordapp.com');
    const maxRequests = isDiscord ? 200 : MAX_REQUESTS_PER_WINDOW; // 200 requests per minute for Discord

    if (!requestTracker.has(domainKey)) {
      requestTracker.set(domainKey, { count: 0, windowStart: now });
    }

    const tracker = requestTracker.get(domainKey);

    // Reset window if needed
    if (now - tracker.windowStart > THROTTLE_WINDOW) {
      tracker.count = 0;
      tracker.windowStart = now;
    }

    // Check if we're over the limit
    if (tracker.count >= maxRequests) {
      const error = new Error(`Rate limit exceeded for domain: ${domain}`);
      error.code = 'ERATE_LIMIT';
      callback(error);
      return;
    }

    tracker.count++;

    super.createConnection(options, (err, socket) => {
      if (socket) {
        // Add error handler to prevent unhandled 'error' events
        socket.on('error', () => {
          // Silently handle socket errors to prevent unhandled exceptions
        });
      }
      callback(err, socket);
    });
  }
}

// Custom HTTPS Agent with browser-like headers and throttling
class CloudflareFriendlyHttpsAgent extends https.Agent {
  constructor(options = {}) {
    super({
      keepAlive: true,
      maxSockets: 10,
      maxFreeSockets: 5,
      timeout: 30000,
      rejectUnauthorized: false, // Allow self-signed certificates
      ...options
    });
  }

  createConnection(options, callback) {
    // Add throttling check
    const domain = options.host || options.hostname;
    const now = Date.now();
    const domainKey = `${domain}`;

    // Higher limits for Discord domains
    const isDiscord = domain.includes('discord.com') || domain.includes('discordapp.com');
    const maxRequests = isDiscord ? 200 : MAX_REQUESTS_PER_WINDOW; // 200 requests per minute for Discord

    if (!requestTracker.has(domainKey)) {
      requestTracker.set(domainKey, { count: 0, windowStart: now });
    }

    const tracker = requestTracker.get(domainKey);

    // Reset window if needed
    if (now - tracker.windowStart > THROTTLE_WINDOW) {
      tracker.count = 0;
      tracker.windowStart = now;
    }

    // Check if we're over the limit
    if (tracker.count >= maxRequests) {
      const error = new Error(`Rate limit exceeded for domain: ${domain}`);
      error.code = 'ERATE_LIMIT';
      callback(error);
      return;
    }

    tracker.count++;

    super.createConnection(options, (err, socket) => {
      if (socket) {
        // Add error handler to prevent unhandled 'error' events
        socket.on('error', () => {
          // Silently handle socket errors to prevent unhandled exceptions
        });
      }
      callback(err, socket);
    });
  }
}

// Create custom agents
const httpAgent = new CloudflareFriendlyHttpAgent();
const httpsAgent = new CloudflareFriendlyHttpsAgent();

// Browser-like headers to avoid Cloudflare detection
const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'DNT': '1',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Cache-Control': 'max-age=0',
  'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  'Sec-Ch-Ua-Mobile': '?0',
  'Sec-Ch-Ua-Platform': '"Windows"'
};

// Create bare server with default agents (temporarily disable custom agents to test)
const bareServer = createBareServer("/ca/", {
  // httpAgent,
  // httpsAgent,
  // Add custom request interceptor to set headers and handle cookies
  filterRemote: async (remote) => {
    // Allow all remotes for now, but we could add filtering here
  }
});



const PORT = process.env.PORT || 8080;
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // Cache for 30 Days
let isLockedDown = false;
const suspectLogs = [];

// Metrics data structures
const metrics = {
  networkTraffic: new Map(), // domain -> { timestamps: [], counts: [] }
  visitedSites: new Map(), // domain -> visit count
  activeSessions: new Map(), // ip_domain -> { startTime, lastActivity, requestCount }
  trafficHistory: [] // { timestamp, requests, dataTransferred }
};

// Rate limiting for API endpoints
const apiRateLimit = new Map();
const API_RATE_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_API_REQUESTS = 100; // 100 requests per 15 minutes per IP

function checkApiRateLimit(ip) {
  const now = Date.now();
  const key = ip;

  if (!apiRateLimit.has(key)) {
    apiRateLimit.set(key, { count: 0, windowStart: now });
  }

  const rateData = apiRateLimit.get(key);

  // Reset window if needed
  if (now - rateData.windowStart > API_RATE_WINDOW) {
    rateData.count = 0;
    rateData.windowStart = now;
  }

  if (rateData.count >= MAX_API_REQUESTS) {
    return false; // Rate limit exceeded
  }

  rateData.count++;
  return true;
}

// CSRF protection middleware for API endpoints
const csrfTokens = new Map();
const CSRF_TOKEN_CLEANUP_TIME = 60 * 60 * 1000; // 1 hour

function generateCsrfToken(sessionId) {
  const token = crypto.randomBytes(32).toString('hex');
  csrfTokens.set(sessionId, { token, timestamp: Date.now() });
  return token;
}

function validateCsrfToken(sessionId, token) {
  const stored = csrfTokens.get(sessionId);
  if (!stored || stored.token !== token) {
    return false;
  }

  // Clean up old tokens
  if (Date.now() - stored.timestamp > CSRF_TOKEN_CLEANUP_TIME) {
    csrfTokens.delete(sessionId);
    return false;
  }

  return true;
}

// Security middleware
function securityMiddleware(req, res, next) {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // CSP header (restrictive)
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://particlesjs.com https://*.particlesjs.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
    "img-src 'self' data: https: blob:; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self' wss: ws: https:; " +
    "media-src 'self' data: blob:; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';"
  );

  // Generate and set CSRF token for API routes
  if (req.path.startsWith('/api/') && req.method !== 'GET') {
    const clientIP = req.ip || req.connection.remoteAddress;
    const sessionId = `csrf_${clientIP}_${Date.now()}`;
    const csrfToken = generateCsrfToken(sessionId);

    // Return CSRF token in response header
    res.setHeader('X-CSRF-Token', csrfToken);
  }

  next();
}

// CORS configuration (more restrictive)
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    // For now, allow localhost and any domain that matches our host
    const allowedOrigins = [
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'https://localhost:8080',
      'https://127.0.0.1:8080'
    ];

    // Allow if origin is in allowed list or if it's served from the same host
    if (allowedOrigins.includes(origin) || origin.includes(req.headers.host)) {
      return callback(null, true);
    }

    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
};

// Clean up old metrics data periodically
setInterval(() => {
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  const oneDay = 24 * oneHour;

  // Clean up old network traffic data (keep last 24 hours)
  for (const [domain, data] of metrics.networkTraffic) {
    const recentData = data.timestamps.filter(ts => now - ts < oneDay);
    if (recentData.length === 0) {
      metrics.networkTraffic.delete(domain);
    } else {
      data.timestamps = recentData;
      data.counts = data.counts.slice(-recentData.length);
    }
  }

  // Clean up old active sessions (inactive for 30 minutes)
  for (const [key, session] of metrics.activeSessions) {
    if (now - session.lastActivity > 30 * 60 * 1000) {
      metrics.activeSessions.delete(key);
    }
  }

  // Keep only last 24 hours of traffic history
  metrics.trafficHistory = metrics.trafficHistory.filter(entry => now - entry.timestamp < oneDay);
}, 5 * 60 * 1000); // Clean up every 5 minutes

// Function to collect metrics
const collectMetrics = (ip, domain, dataTransferred = 0) => {
  const now = Date.now();

  // Update network traffic per domain
  if (!metrics.networkTraffic.has(domain)) {
    metrics.networkTraffic.set(domain, { timestamps: [], counts: [] });
  }
  const domainData = metrics.networkTraffic.get(domain);
  domainData.timestamps.push(now);
  domainData.counts.push((domainData.counts[domainData.counts.length - 1] || 0) + 1);

  // Keep only last 100 data points per domain
  if (domainData.timestamps.length > 100) {
    domainData.timestamps.shift();
    domainData.counts.shift();
  }

  // Update visited sites count
  metrics.visitedSites.set(domain, (metrics.visitedSites.get(domain) || 0) + 1);

  // Update active sessions
  const sessionKey = `${ip}_${domain}`;
  if (!metrics.activeSessions.has(sessionKey)) {
    metrics.activeSessions.set(sessionKey, {
      startTime: now,
      lastActivity: now,
      requestCount: 0,
      domain: domain
    });
  }
  const session = metrics.activeSessions.get(sessionKey);
  session.lastActivity = now;
  session.requestCount++;

  // Update traffic history (aggregate per minute)
  const minuteTimestamp = Math.floor(now / 60000) * 60000; // Round to nearest minute
  let lastEntry = metrics.trafficHistory[metrics.trafficHistory.length - 1];
  if (!lastEntry || lastEntry.timestamp !== minuteTimestamp) {
    lastEntry = { timestamp: minuteTimestamp, requests: 0, dataTransferred: 0 };
    metrics.trafficHistory.push(lastEntry);
    // Keep only last 24 hours (1440 minutes)
    if (metrics.trafficHistory.length > 1440) {
      metrics.trafficHistory.shift();
    }
  }
  lastEntry.requests++;
  lastEntry.dataTransferred += dataTransferred;
};

// Function to log suspect activity
const logSuspectActivity = (ip, domain) => {
  suspectLogs.push({
    ip,
    domain,
    timestamp: new Date().toISOString()
  });
  // Keep only last 100 logs
  if (suspectLogs.length > 100) {
    suspectLogs.shift();
  }
};

if (config.challenge !== false) {
  console.log(chalk.green("🔒 Password protection is enabled! Listing logins below"));
  // biome-ignore lint: idk
  Object.entries(config.users).forEach(([username, password]) => {
    console.log(chalk.blue(`Username: ${username}, Password: ${password}`));
  });
  app.use(basicAuth({ users: config.users, challenge: true }));
}

// Lockdown middleware
app.use((req, res, next) => {
  if (isLockedDown && !req.path.startsWith('/admin')) {
    return res.status(403).send('403 Unauthorized - Site is in lockdown mode');
  }
  next();
});

// Admin auth middleware
const adminAuth = (req, res, next) => {
  const auth = { login: process.env.ADMIN_USER, password: process.env.ADMIN_PASS };
  const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
  const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');
  if (login && password && login === auth.login && password === auth.password) {
    return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Admin Panel"');
  res.status(401).send('Authentication required');
};

app.get("/e/*", async (req, res, next) => {
  try {
    if (cache.has(req.path)) {
      const { data, contentType, timestamp } = cache.get(req.path);
      if (Date.now() - timestamp > CACHE_TTL) {
        cache.delete(req.path);
      } else {
        res.writeHead(200, { "Content-Type": contentType });
        return res.end(data);
      }
    }

    const baseUrls = {
      "/e/1/": "https://raw.githubusercontent.com/qrs/x/fixy/",
      "/e/2/": "https://raw.githubusercontent.com/3v1/V5-Assets/main/",
      "/e/3/": "https://raw.githubusercontent.com/3v1/V5-Retro/master/",
    };

    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }

    if (!reqTarget) {
      return next();
    }

    const asset = await fetch(reqTarget);
    if (!asset.ok) {
      return next();
    }

    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = [".unityweb"];
    const contentType = no.includes(ext) ? "application/octet-stream" : mime.getType(ext);

    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.setHeader("Content-Type", "text/html");
    res.status(500).send("Error fetching the asset");
  }
});

// SQL Injection Detection Middleware
function detectSQLInjection(obj, path = '') {
  const sqlPatterns = [
    /(\bUNION\b\s+\bSELECT\b)/i,
    /(\bDROP\b\s+\bTABLE\b)/i,
    /(\bINSERT\b\s+\bINTO\b)/i,
    /(\bUPDATE\b.*?\bSET\b)/i,
    /(\bDELETE\b\s+\bFROM\b)/i,
    /(\bSELECT\b.*?\bFROM\b)/i,
    /(\bALTER\b\s+\bTABLE\b)/i,
    /(\bCREATE\b\s+\bTABLE\b)/i,
    /(\bEXEC\b)/i,
    /(\bEXECUTE\b)/i,
    /['";\\*?+{}[\]()]/,  // Common SQL injection characters
    /(\bor\b\s+1\s*=\s*1)/i,
    /(\band\b\s+1\s*=\s*1)/i,
    /(--)/,
    /(\/\*.*?\*\/)/,
    /(\#)/,
    /(\\x[0-9a-f]{2})/i,
    /(\\u[0-9a-f]{4})/i
  ];

  function checkValue(value, currentPath) {
    if (typeof value === 'string') {
      for (const pattern of sqlPatterns) {
        if (pattern.test(value)) {
          console.log(`SQL Injection detected in ${currentPath}: ${value}`);
          return true;
        }
      }
    } else if (typeof value === 'object' && value !== null) {
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          if (checkValue(value[i], `${currentPath}[${i}]`)) {
            return true;
          }
        }
      } else {
        for (const [key, val] of Object.entries(value)) {
          if (checkValue(val, `${currentPath}.${key}`)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  return checkValue(obj, path);
}

app.use((req, res, next) => {
  // Check request body
  if (req.body && detectSQLInjection(req.body, 'body')) {
    return res.status(500).send('Internal Server Error');
  }

  // Check query parameters
  if (req.query && detectSQLInjection(req.query, 'query')) {
    return res.status(500).send('Internal Server Error');
  }

  // Check route parameters
  if (req.params && detectSQLInjection(req.params, 'params')) {
    return res.status(500).send('Internal Server Error');
  }

  next();
});

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security middleware
app.use(securityMiddleware);

// Rate limiting for API endpoints
app.use('/api/', (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  if (!checkApiRateLimit(clientIP)) {
    return res.status(429).json({ message: 'Too many requests. Please try again later.' });
  }
  next();
});

// Cookie fingerprinting middleware
app.use((req, res, next) => {
  if (!req.cookies.deviceFingerprint) {
    // Generate a simple fingerprint based on IP and user agent
    const fingerprint = Buffer.from(`${req.ip}-${req.get('User-Agent')}`).toString('base64').substring(0, 32);
    res.cookie('deviceFingerprint', fingerprint, {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      httpOnly: true,
      secure: req.protocol === 'https',
      sameSite: 'strict'
    });
  }
  next();
});

/* if (process.env.MASQR === "true") {
  console.log(chalk.green("Masqr is enabled"));
  setupMasqr(app);
} */

app.use(express.static(path.join(__dirname, "static")));
app.use("/ca", cors({ origin: true }));

// Authentication is handled client-side

// Auth API endpoints
app.post('/api/signin', (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    const user = getUser(username);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    let decryptedPassword;
    try {
      decryptedPassword = decryptPassword(user.password);
    } catch (error) {
      console.error('Password decryption error:', error);
      return res.status(500).json({ message: 'Internal server error during signin' });
    }

    if (decryptedPassword !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (user.pending) {
      return res.status(403).json({ message: 'Account is pending approval. Please wait for admin approval.' });
    }

    // Generate device token
    const deviceToken = crypto.randomBytes(32).toString('hex');

    // Store device token in database
    updateDeviceToken(user.id, deviceToken);

    res.json({
      message: 'Sign in successful',
      deviceToken: deviceToken
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ message: 'Internal server error during signin' });
  }
});

// Device token validation endpoint
app.post('/api/validate-token', (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ valid: false });
  }

  const user = getUserByDeviceToken(deviceToken);
  if (!user || user.pending) {
    return res.json({ valid: false });
  }

  res.json({ valid: true, user: { username: user.username } });
});

app.post('/api/request-account', (req, res) => {
  const { username, password, referralCode } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ message: 'Username must be at least 3 characters, password at least 6 characters' });
  }

  try {
    const encryptedPassword = encryptPassword(password);
    const userId = createUserWithReferral(username, encryptedPassword, referralCode);

    // Generate referral code for the new user
    setUserReferralCode(userId);

    res.json({ message: 'Account request submitted successfully' });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ message: 'Username already exists' });
    }
    res.status(500).json({ message: 'Failed to create account request' });
  }
});

app.post('/api/signout', (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    sessions.delete(sessionId);
    res.clearCookie('sessionId');
  }
  res.json({ message: 'Signed out successfully' });
});

// Routes for auth pages
app.get('/signin', (req, res) => {
  res.sendFile(path.join(process.cwd(), "static", "signin.html"));
});

app.get('/request', (req, res) => {
  res.sendFile(path.join(__dirname, "static", "request.html"));
});

// Admin routes
app.get('/admin', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        button { padding: 10px 20px; margin: 10px; cursor: pointer; }
        .logs { margin-top: 20px; }
        .log-entry { border: 1px solid #ccc; padding: 10px; margin: 5px 0; }
        .user-entry { border: 1px solid #ddd; padding: 10px; margin: 5px 0; display: flex; justify-content: space-between; align-items: center; }
        .user-info { flex-grow: 1; }
        .user-actions { display: flex; gap: 10px; }
        .pending { color: orange; font-weight: bold; }
        .approved { color: green; font-weight: bold; }
        input, select { padding: 5px; margin: 5px; }
        .edit-form { display: none; margin-top: 10px; padding: 10px; background: #f9f9f9; }
      </style>
    </head>
    <body>
      <h1>Admin Panel</h1>
      <div>
        <button onclick="loadTerminal()">Load Reverse TCP Terminal</button>
        <button onclick="loadSSH()">Load SSH Terminal</button>
        <button onclick="signInAsAdmin()">Sign in as Admin (Chat)</button>
        <button onclick="viewLogs()">View Logs</button>
        <button onclick="manageUsers()">Manage Users</button>
        <button onclick="manageMessages()">Manage Messages</button>
        <button onclick="viewReferrals()">View Referrals</button>
        <button onclick="manageSearchHistory()">Manage Search History</button>
        <button onclick="toggleLockdown()">${isLockedDown ? 'Lift Lockdown' : 'Activate Lockdown'}</button>
      </div>
      <div id="content"></div>
      <script>
        function loadTerminal() {
          window.open('/admin/terminal', '_blank');
        }
        function loadSSH() {
          window.open('/admin/ssh', '_blank');
        }
        function signInAsAdmin() {
          window.open('/chat?admin=true', '_blank');
        }
        function viewLogs() {
          fetch('/admin/logs')
            .then(res => res.json())
            .then(logs => {
              const html = logs.map(log =>
                \`<div class="log-entry">
                  <strong>IP:</strong> \${log.ip}<br>
                  <strong>Domain:</strong> \${log.domain}<br>
                  <strong>Timestamp:</strong> \${new Date(log.timestamp).toLocaleString()}
                </div>\`
              ).join('');
              document.getElementById('content').innerHTML = '<h2>Suspect Logs</h2>' + html;
            });
        }
        function manageUsers() {
          fetch('/admin/users')
            .then(res => res.json())
            .then(users => {
              const html = users.map(user =>
                \`<div class="user-entry">
                  <div class="user-info">
                    <strong>ID:</strong> \${user.id}<br>
                    <strong>Username:</strong> \${user.username}<br>
                    <strong>Status:</strong> <span class="\${user.pending ? 'pending' : 'approved'}">\${user.pending ? 'PENDING' : 'APPROVED'}</span><br>
                    <strong>Created:</strong> \${new Date(user.created_at).toLocaleString()}<br>
                    \${user.referral_code_used ? \`<strong>Referral Code Used:</strong> \${user.referral_code_used}<br>\` : ''}
                    \${user.referrer_username ? \`<strong>Referred By:</strong> \${user.referrer_username} (ID: \${user.referrer_user_id})<br>\` : ''}
                    \${user.referral_used_at ? \`<strong>Referral Used:</strong> \${new Date(user.referral_used_at).toLocaleString()}<br>\` : ''}
                  </div>
                  <div class="user-actions">
                    <button onclick="editUser(\${user.id}, '\${user.username}', \${user.pending})">Edit</button>
                    <button onclick="deleteUser(\${user.id})" style="background: red; color: white;">Delete</button>
                  </div>
                  <div id="edit-\${user.id}" class="edit-form">
                    <h4>Edit User \${user.id}</h4>
                    <input type="text" id="username-\${user.id}" value="\${user.username}" placeholder="Username">
                    <input type="password" id="password-\${user.id}" placeholder="New Password (leave empty to keep current)">
                    <select id="pending-\${user.id}">
                      <option value="false" \${!user.pending ? 'selected' : ''}>Approved</option>
                      <option value="true" \${user.pending ? 'selected' : ''}>Pending</option>
                    </select>
                    <button onclick="saveUser(\${user.id})">Save</button>
                    <button onclick="cancelEdit(\${user.id})">Cancel</button>
                  </div>
                </div>\`
              ).join('');
              document.getElementById('content').innerHTML = '<h2>User Management</h2>' + html;
            });
        }
        function editUser(id, username, pending) {
          document.getElementById(\`edit-\${id}\`).style.display = 'block';
        }
        function cancelEdit(id) {
          document.getElementById(\`edit-\${id}\`).style.display = 'none';
        }
        function saveUser(id) {
          const username = document.getElementById(\`username-\${id}\`).value;
          const password = document.getElementById(\`password-\${id}\`).value;
          const pending = document.getElementById(\`pending-\${id}\`).value === 'true';

          const updates = { username, pending };
          if (password) updates.password = password;

          fetch(\`/admin/users/\${id}\`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates),
            credentials: 'include'
          })
          .then(res => {
            if (res.status === 401) {
              alert('Admin authentication required');
              return;
            }
            return res.json();
          })
          .then(result => {
            if (result) {
              alert(result.message);
              manageUsers();
            }
          })
          .catch(err => alert('Error updating user: ' + err.message));
        }
        function deleteUser(id) {
          if (confirm('Are you sure you want to delete this user?')) {
            fetch(\`/admin/users/\${id}\`, {
              method: 'DELETE',
              credentials: 'include'
            })
            .then(res => {
              if (res.status === 401) {
                alert('Admin authentication required');
                return;
              }
              return res.json();
            })
            .then(result => {
              if (result) {
                alert(result.message);
                manageUsers();
              }
            })
            .catch(err => alert('Error deleting user: ' + err.message));
          }
        }
        function manageMessages() {
          fetch('/admin/messages')
            .then(res => res.json())
            .then(messages => {
              const html = messages.map(msg =>
                \`<div class="user-entry">
                  <div class="user-info">
                    <strong>ID:</strong> \${msg.id}<br>
                    <strong>Message:</strong> \${msg.message}<br>
                    <strong>Active:</strong> \${msg.active ? 'Yes' : 'No'}<br>
                    <strong>Created:</strong> \${new Date(msg.created_at).toLocaleString()}
                  </div>
                  <div class="user-actions">
                    <button onclick="editMessage(\${msg.id}, '\${msg.message.replace(/'/g, "\\'")}', \${msg.active})">Edit</button>
                    <button onclick="deleteMessage(\${msg.id})" style="background: red; color: white;">Delete</button>
                  </div>
                  <div id="edit-msg-\${msg.id}" class="edit-form">
                    <h4>Edit Message \${msg.id}</h4>
                    <textarea id="message-\${msg.id}" rows="3" style="width: 100%;">\${msg.message}</textarea>
                    <label><input type="checkbox" id="active-\${msg.id}" \${msg.active ? 'checked' : ''}> Active</label>
                    <button onclick="saveMessage(\${msg.id})">Save</button>
                    <button onclick="cancelEditMessage(\${msg.id})">Cancel</button>
                  </div>
                </div>\`
              ).join('');
              const createForm = \`<div class="user-entry">
                <h3>Create New Message</h3>
                <textarea id="new-message" rows="3" placeholder="Enter message" style="width: 100%;"></textarea>
                <label><input type="checkbox" id="new-active" checked> Active</label>
                <button onclick="createMessage()">Create Message</button>
              </div>\`;
              document.getElementById('content').innerHTML = '<h2>Message Management</h2>' + createForm + html;
            });
        }
        function editMessage(id, message, active) {
          document.getElementById(\`edit-msg-\${id}\`).style.display = 'block';
        }
        function cancelEditMessage(id) {
          document.getElementById(\`edit-msg-\${id}\`).style.display = 'none';
        }
        function saveMessage(id) {
          const message = document.getElementById(\`message-\${id}\`).value;
          const active = document.getElementById(\`active-\${id}\`).checked;

          fetch(\`/admin/messages/\${id}\`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, active }),
            credentials: 'include'
          })
          .then(res => res.json())
          .then(result => {
            alert(result.message);
            manageMessages();
          })
          .catch(err => alert('Error updating message: ' + err.message));
        }
        function deleteMessage(id) {
          if (confirm('Are you sure you want to delete this message?')) {
            fetch(\`/admin/messages/\${id}\`, {
              method: 'DELETE',
              credentials: 'include'
            })
            .then(res => res.json())
            .then(result => {
              alert(result.message);
              manageMessages();
            })
            .catch(err => alert('Error deleting message: ' + err.message));
          }
        }
        function createMessage() {
          const message = document.getElementById('new-message').value;
          const active = document.getElementById('new-active').checked;

          if (!message.trim()) {
            alert('Message cannot be empty');
            return;
          }

          fetch('/admin/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, active }),
            credentials: 'include'
          })
          .then(res => res.json())
          .then(result => {
            alert(result.message);
            manageMessages();
          })
          .catch(err => alert('Error creating message: ' + err.message));
        }
        function viewReferrals() {
          fetch('/admin/referrals')
            .then(res => res.json())
            .then(referrals => {
              const html = referrals.map(ref =>
                \`<div class="user-entry">
                  <div class="user-info">
                    <strong>Referrer:</strong> \${ref.referrer_username}<br>
                    <strong>Referred User:</strong> \${ref.referred_username}<br>
                    <strong>Referred Date:</strong> \${new Date(ref.referred_at).toLocaleString()}
                  </div>
                </div>\`
              ).join('');
              document.getElementById('content').innerHTML = '<h2>Referral Information</h2>' + html;
            });
        }
        function manageSearchHistory() {
          window.open('/search-history', '_blank');
        }
        function toggleLockdown() {
          const action = '${isLockedDown ? 'unlock' : 'lockdown'}';
          fetch('/admin/' + action, { method: 'POST' })
            .then(() => location.reload());
        }
      </script>
    </body>
    </html>
  `);
});

// Admin search history routes
app.get('/admin/search-history', adminAuth, async (req, res) => {
  try {
    // Get all search history with user information
    const stmt = db.prepare(`
      SELECT 
        sh.id,
        sh.user_id,
        sh.url,
        sh.title,
        sh.visited_at,
        u.username
      FROM search_history sh
      JOIN users u ON sh.user_id = u.id
      ORDER BY sh.visited_at DESC
      LIMIT 1000
    `);
    const history = stmt.all();
    
    // Add domain extraction
    const historyWithDomains = history.map(item => ({
      ...item,
      domain: extractDomain(item.url)
    }));
    
    res.json(historyWithDomains);
  } catch (error) {
    console.error('Error fetching search history:', error);
    res.status(500).json({ message: 'Failed to fetch search history' });
  }
});

app.get('/admin/search-history/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const stmt = db.prepare(`
      SELECT 
        sh.id,
        sh.user_id,
        sh.url,
        sh.title,
        sh.visited_at,
        u.username
      FROM search_history sh
      JOIN users u ON sh.user_id = u.id
      WHERE sh.id = ?
    `);
    const history = stmt.get(id);
    
    if (!history) {
      return res.status(404).json({ message: 'Search history entry not found' });
    }
    
    res.json({
      ...history,
      domain: extractDomain(history.url)
    });
  } catch (error) {
    console.error('Error fetching search history entry:', error);
    res.status(500).json({ message: 'Failed to fetch search history entry' });
  }
});

app.delete('/admin/search-history/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const stmt = db.prepare('DELETE FROM search_history WHERE id = ?');
    const result = stmt.run(id);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Search history entry not found' });
    }
    
    res.json({ message: 'Search history entry deleted successfully' });
  } catch (error) {
    console.error('Error deleting search history entry:', error);
    res.status(500).json({ message: 'Failed to delete search history entry' });
  }
});

app.delete('/admin/search-history', adminAuth, async (req, res) => {
  try {
    const stmt = db.prepare('DELETE FROM search_history');
    stmt.run();
    res.json({ message: 'All search history cleared successfully' });
  } catch (error) {
    console.error('Error clearing search history:', error);
    res.status(500).json({ message: 'Failed to clear search history' });
  }
});

app.delete('/admin/search-history/bulk', adminAuth, async (req, res) => {
  try {
    const { history_ids } = req.body;
    if (!history_ids || !Array.isArray(history_ids)) {
      return res.status(400).json({ message: 'history_ids array is required' });
    }
    
    const placeholders = history_ids.map(() => '?').join(',');
    const stmt = db.prepare(`DELETE FROM search_history WHERE id IN (${placeholders})`);
    stmt.run(...history_ids);
    
    res.json({ message: 'Selected search history entries deleted successfully' });
  } catch (error) {
    console.error('Error deleting search history entries:', error);
    res.status(500).json({ message: 'Failed to delete search history entries' });
  }
});

app.delete('/admin/search-history/user-bulk', adminAuth, async (req, res) => {
  try {
    const { user_ids } = req.body;
    if (!user_ids || !Array.isArray(user_ids)) {
      return res.status(400).json({ message: 'user_ids array is required' });
    }
    
    const placeholders = user_ids.map(() => '?').join(',');
    const stmt = db.prepare(`DELETE FROM search_history WHERE user_id IN (${placeholders})`);
    stmt.run(...user_ids);
    
    res.json({ message: 'Search history for selected users deleted successfully' });
  } catch (error) {
    console.error('Error deleting user search history:', error);
    res.status(500).json({ message: 'Failed to delete user search history' });
  }
});

// Helper function to extract domain from URL
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return 'unknown';
  }
}

app.get('/admin/logs', adminAuth, (req, res) => {
  res.json(suspectLogs);
});

app.post('/admin/lockdown', adminAuth, (req, res) => {
  isLockedDown = true;
  res.json({ status: 'locked down' });
});

app.post('/admin/unlock', adminAuth, (req, res) => {
  isLockedDown = false;
  res.json({ status: 'unlocked' });
});

// Admin user management endpoints
app.get('/admin/users', adminAuth, (req, res) => {
  try {
    const users = getAllUsers();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.put('/admin/users/:id', adminAuth, (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    if (updates.password) {
      updates.password = encryptPassword(updates.password);
    }
    updateUser(parseInt(id), updates);
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update user' });
  }
});

app.delete('/admin/users/:id', adminAuth, (req, res) => {
  const { id } = req.params;

  try {
    deleteUser(parseInt(id));
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

// Admin referrals endpoint
app.get('/admin/referrals', adminAuth, (req, res) => {
  try {
    // Get all users and their referrals
    const allUsers = getAllUsers();
    const referrals = [];

    for (const user of allUsers) {
      const userReferrals = getUserReferrals(user.id);
      for (const referral of userReferrals) {
        referrals.push({
          referrer_username: user.username,
          referred_username: referral.username,
          referred_at: referral.created_at
        });
      }
    }

    res.json(referrals);
  } catch (error) {
    console.error('Error fetching referrals:', error);
    res.status(500).json({ message: 'Failed to fetch referrals' });
  }
});

// Admin message management endpoints
app.get('/admin/messages', adminAuth, (req, res) => {
  try {
    const messages = getAllMessages();
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/admin/messages', adminAuth, (req, res) => {
  const { message, active } = req.body;

  if (!message || message.trim() === '') {
    return res.status(400).json({ message: 'Message is required' });
  }

  try {
    const msg = createMessage(message.trim());
    // Broadcast notification to all connected users
    const newMessage = { id: msg.lastInsertRowid, message: message.trim(), created_at: new Date().toISOString() };
    broadcastNotification(newMessage);
    res.json({ message: 'Message created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create message' });
  }
});

app.put('/admin/messages/:id', adminAuth, (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    updateMessage(parseInt(id), updates);
    res.json({ message: 'Message updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update message' });
  }
});

app.delete('/admin/messages/:id', adminAuth, (req, res) => {
  const { id } = req.params;

  try {
    deleteMessage(parseInt(id));
    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete message' });
  }
});

// Public API endpoints for messages
app.get('/api/messages', (req, res) => {
  try {
    const messages = getActiveMessages();
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/api/dismiss-message', (req, res) => {
  const { deviceToken, messageId } = req.body;

  if (!deviceToken || !messageId) {
    return res.status(400).json({ message: 'Device token and message ID required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    dismissMessage(user.id, parseInt(messageId));
    res.json({ message: 'Message dismissed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to dismiss message' });
  }
});

app.get('/api/undismissed-messages', (req, res) => {
  const { deviceToken } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const messages = getUndismissedMessages(user.id);
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch undismissed messages' });
  }
});

// Search history API endpoints
app.post('/api/search-history', (req, res) => {
  const { deviceToken, url, title } = req.body;

  if (!deviceToken || !url) {
    return res.status(400).json({ message: 'Device token and URL required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    addSearchHistory(user.id, url, title);
    res.json({ message: 'Search history entry added successfully' });
  } catch (error) {
    console.error('Error adding search history:', error);
    res.status(500).json({ message: 'Failed to add search history entry' });
  }
});

app.get('/api/search-history', (req, res) => {
  const { deviceToken, limit } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const limitNum = limit ? parseInt(limit) : 50;
    const history = getSearchHistory(user.id, limitNum);
    res.json(history);
  } catch (error) {
    console.error('Error fetching search history:', error);
    res.status(500).json({ message: 'Failed to fetch search history' });
  }
});

app.delete('/api/search-history/:id', (req, res) => {
  const { id } = req.params;
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    deleteSearchHistory(user.id, parseInt(id));
    res.json({ message: 'Search history entry deleted successfully' });
  } catch (error) {
    console.error('Error deleting search history:', error);
    res.status(500).json({ message: 'Failed to delete search history entry' });
  }
});

app.delete('/api/search-history', (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    clearSearchHistory(user.id);
    res.json({ message: 'Search history cleared successfully' });
  } catch (error) {
    console.error('Error clearing search history:', error);
    res.status(500).json({ message: 'Failed to clear search history' });
  }
});

app.get('/admin/terminal', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Reverse TCP Terminal</title>
      <style>
        body { font-family: monospace; margin: 20px; background: black; color: green; }
        #terminal { width: 100%; height: 400px; background: black; color: green; border: none; padding: 10px; }
        input { background: black; color: green; border: 1px solid green; padding: 5px; }
        button { background: black; color: green; border: 1px solid green; padding: 5px 10px; cursor: pointer; }
      </style>
    </head>
    <body>
      <h1>Reverse TCP Terminal</h1>
      <div>
        <input type="text" id="host" placeholder="Host (e.g., 127.0.0.1)" value="127.0.0.1">
        <input type="text" id="port" placeholder="Port (e.g., 4444)" value="4444">
        <button onclick="connect()">Connect</button>
        <button onclick="disconnect()">Disconnect</button>
      </div>
      <textarea id="terminal" readonly></textarea>
      <div>
        <input type="text" id="command" placeholder="Enter command" onkeypress="handleKeyPress(event)">
        <button onclick="sendCommand()">Send</button>
      </div>
      <script>
        let ws = null;
        const terminal = document.getElementById('terminal');

        function log(message) {
          terminal.value += message + '\\n';
          terminal.scrollTop = terminal.scrollHeight;
        }

        function connect() {
          const host = document.getElementById('host').value;
          const port = document.getElementById('port').value;
          const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
          const wsUrl = \`\${protocol}//\${host}:\${port}\`;

          log('Attempting to connect to ' + wsUrl + '...');

          try {
            ws = new WebSocket(wsUrl);

            ws.onopen = function(event) {
              log('Connected to reverse TCP server');
            };

            ws.onmessage = function(event) {
              log(event.data);
            };

            ws.onclose = function(event) {
              log('Connection closed');
              ws = null;
            };

            ws.onerror = function(error) {
              log('Connection error: ' + error);
            };
          } catch (e) {
            log('Failed to connect: ' + e.message);
          }
        }

        function disconnect() {
          if (ws) {
            ws.close();
            ws = null;
          }
          log('Disconnected');
        }

        function sendCommand() {
          const command = document.getElementById('command').value;
          if (command && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(command);
            log('> ' + command);
            document.getElementById('command').value = '';
          } else if (!ws || ws.readyState !== WebSocket.OPEN) {
            log('Not connected');
          }
        }

        function handleKeyPress(event) {
          if (event.key === 'Enter') {
            sendCommand();
          }
        }
      </script>
    </body>
    </html>
  `);
});

app.get('/admin/ssh', adminAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Web SSH Terminal</title>
      <style>
        body { font-family: monospace; margin: 20px; background: black; color: green; }
        #ssh-terminal {
          width: 100%;
          height: 400px;
          background: black;
          color: green;
          border: 1px solid green;
          padding: 10px;
          font-family: monospace;
          font-size: 14px;
          resize: none;
          outline: none;
        }
        input { background: black; color: green; border: 1px solid green; padding: 5px; margin: 5px; }
        button { background: black; color: green; border: 1px solid green; padding: 5px 10px; cursor: pointer; }
        .connection-form { margin-bottom: 20px; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <h1>Web SSH Terminal</h1>
      <div class="connection-form">
        <input type="text" id="ssh-host" placeholder="Host (e.g., localhost)" value="localhost">
        <input type="text" id="ssh-username" placeholder="Username" value="root">
        <button id="ssh-connect">Connect</button>
        <button id="ssh-disconnect">Disconnect</button>
      </div>
      <textarea id="ssh-terminal"></textarea>
      <div class="hidden">
        <input type="text" id="ssh-command">
      </div>
      <script src="/ssh.js"></script>
    </body>
    </html>
  `);
});

// File upload endpoint for AI
app.post('/api/ai/upload', upload.single('image'), (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'No image file provided' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Read the file and convert to base64
    const imageBuffer = fs.readFileSync(req.file.path);
    const base64Image = imageBuffer.toString('base64');
    const mimeType = req.file.mimetype;

    // Clean up the uploaded file
    fs.unlinkSync(req.file.path);

    // Return base64 data for the AI to use
    res.json({
      imageData: `data:${mimeType};base64,${base64Image}`,
      mimeType
    });
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ message: 'Failed to upload file' });
  }
});

// Serve uploaded files
app.use('/uploads', express.static(uploadsDir));

// DuckDuckGo search function
async function searchDuckDuckGo(query) {
  try {
    const searchUrl = `https://duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const response = await fetch(searchUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
      }
    });

    if (!response.ok) {
      throw new Error('Search request failed');
    }

    const html = await response.text();

    // Simple parsing of DuckDuckGo results (this is basic - in production you'd want better parsing)
    const results = [];
    const resultRegex = /<a class="result__a" href="([^"]*)"[^>]*>([^<]*)<\/a>/g;
    let match;

    while ((match = resultRegex.exec(html)) && results.length < 5) {
      const url = match[1];
      const title = match[2].replace(/<[^>]*>/g, ''); // Remove any remaining HTML tags
      if (url && title) {
        results.push({ title, url });
      }
    }

    return results;
  } catch (error) {
    console.error('DuckDuckGo search error:', error);
    return [];
  }
}

// AI Chat API endpoints
app.get('/api/ai/chats', (req, res) => {
  const { deviceToken } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const chats = getAIChats(user.id);
    res.json(chats);
  } catch (error) {
    console.error('Error fetching AI chats:', error);
    res.status(500).json({ message: 'Failed to fetch AI chats' });
  }
});

app.post('/api/ai/chats', (req, res) => {
  const { deviceToken, title } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const chatId = createAIChat(user.id, title);
    res.json({ chatId });
  } catch (error) {
    console.error('Error creating AI chat:', error);
    res.status(500).json({ message: 'Failed to create AI chat' });
  }
});

app.get('/api/ai/chats/:chatId/messages', (req, res) => {
  const { chatId } = req.params;
  const { deviceToken } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const chat = getAIChat(parseInt(chatId), user.id);
    if (!chat) {
      return res.status(404).json({ message: 'Chat not found' });
    }

    // Get or create AES key for this user
    const aesKey = ensureUserAESKey(user.id);

    const messages = getAIMessages(parseInt(chatId));

    // Decrypt messages before returning (handle legacy unencrypted messages)
    const decryptedMessages = messages.map(msg => {
      try {
        return {
          ...msg,
          content: decryptAES128(msg.content, aesKey)
        };
      } catch (error) {
        // If decryption fails, assume it's not encrypted (legacy data)
        return msg;
      }
    });

    res.json(decryptedMessages);
  } catch (error) {
    console.error('Error fetching AI messages:', error);
    res.status(500).json({ message: 'Failed to fetch AI messages' });
  }
});

app.post('/api/ai/chats/:chatId/messages', async (req, res) => {
  const { chatId } = req.params;
  const { deviceToken, message, imageData } = req.body;

  if (!deviceToken || !message) {
    return res.status(400).json({ message: 'Device token and message required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const chat = getAIChat(parseInt(chatId), user.id);
    if (!chat) {
      return res.status(404).json({ message: 'Chat not found' });
    }

    // Get or create AES key for this user
    const aesKey = ensureUserAESKey(user.id);

    // Encrypt the user message
    let messageContent = message;
    if (imageData) {
      messageContent = `Image: ${imageData}\n\n${message}`;
    }
    const encryptedMessage = encryptAES128(messageContent, aesKey);
    addAIMessage(parseInt(chatId), 'user', encryptedMessage);

    // Get conversation history
    const messages = getAIMessages(parseInt(chatId));
    const conversation = [
      {
        role: 'system',
        content: 'You are a helpful AI assistant. When users ask questions that require current information, real-time data, or web searches, use the format [SEARCH:query] in your response to search DuckDuckGo. For example, if asked "What is the current weather in New York?", respond with [SEARCH:current weather in New York]. The search results will be provided to you automatically. You can also analyze images when provided.'
      },
      ...messages.map(msg => {
        // Decrypt message content for API call
        let decryptedContent;
        try {
          decryptedContent = decryptAES128(msg.content, aesKey);
        } catch (error) {
          // If decryption fails, assume it's not encrypted (legacy data)
          decryptedContent = msg.content;
        }

        // Handle image messages for vision models
        if (decryptedContent.startsWith('Image: ')) {
          const imageMatch = decryptedContent.match(/^Image: (data:[^;]+;base64,[^\s]+)\n\n(.+)$/);
          if (imageMatch) {
            return {
              role: msg.role,
              content: [
                {
                  type: 'image_url',
                  image_url: { url: imageMatch[1] }
                },
                {
                  type: 'text',
                  text: imageMatch[2]
                }
              ]
            };
          }
        }
        return {
          role: msg.role,
          content: decryptedContent
        };
      })
    ];

    // Call OpenRouter API
    const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
    if (!OPENROUTER_API_KEY) {
      return res.status(500).json({ message: 'AI service not configured' });
    }

    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': req.headers.referer || req.headers.origin || 'http://localhost',
        'X-Title': 'Interstellar AI Chat'
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: conversation,
        max_tokens: 4096,
        temperature: 0.7
      })
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('OpenRouter API error:', error);
      return res.status(500).json({ message: 'AI service error' });
    }

    const data = await response.json();
    let aiResponse = data.choices[0]?.message?.content;

    if (!aiResponse) {
      return res.status(500).json({ message: 'No response from AI' });
    }

    // Check if AI wants to search DuckDuckGo
    const searchMatch = aiResponse.match(/\[SEARCH:(.+?)\]/);
    if (searchMatch) {
      const searchQuery = searchMatch[1].trim();
      const searchResults = await searchDuckDuckGo(searchQuery);

      if (searchResults.length > 0) {
        const searchSummary = `Search results for "${searchQuery}":\n\n` +
          searchResults.map((result, index) =>
            `${index + 1}. ${result.title}\n   ${result.url}`
          ).join('\n\n');

        // Add search results to AI response
        aiResponse = aiResponse.replace(/\[SEARCH:.+?\]/, searchSummary);
      } else {
        aiResponse = aiResponse.replace(/\[SEARCH:.+?\]/, `No search results found for "${searchQuery}".`);
      }
    }

    // Encrypt the AI response
    const encryptedResponse = encryptAES128(aiResponse, aesKey);
    addAIMessage(parseInt(chatId), 'assistant', encryptedResponse);

    res.json({ response: aiResponse });
  } catch (error) {
    console.error('Error sending AI message:', error);
    res.status(500).json({ message: 'Failed to send AI message' });
  }
});

app.delete('/api/ai/chats/:chatId', (req, res) => {
  const { chatId } = req.params;
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    deleteAIChat(parseInt(chatId), user.id);
    res.json({ message: 'Chat deleted successfully' });
  } catch (error) {
    console.error('Error deleting AI chat:', error);
    res.status(500).json({ message: 'Failed to delete AI chat' });
  }
});

// Account management API endpoints
app.post('/api/account-info', (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Get referral code from separate database
    let referralCode = null;

    if (referDb) {
      try {
        const stmt = referDb.prepare('SELECT code FROM referral_codes WHERE user_id = ?');
        const result = stmt.get(user.id);
        if (result) {
          referralCode = result.code;
        }
      } catch (error) {
        // Table might not exist yet
        console.log('Referral codes table not ready');
      }
    }

    // Generate new referral code if none exists
    if (!referralCode) {
      referralCode = setUserReferralCode(user.id);
    }

    res.json({
      success: true,
      username: user.username,
      created_at: user.created_at,
      referral_code: referralCode
    });
  } catch (error) {
    console.error('Error fetching account info:', error);
    res.status(500).json({ message: 'Failed to fetch account info' });
  }
});

app.post('/api/change-password', (req, res) => {
  const { deviceToken, currentPassword, newPassword } = req.body;

  if (!deviceToken || !currentPassword || !newPassword) {
    return res.status(400).json({ message: 'All fields required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'New password must be at least 6 characters' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Verify current password
    let decryptedPassword;
    try {
      decryptedPassword = decryptPassword(user.password);
    } catch (error) {
      console.error('Password decryption error:', error);
      return res.status(500).json({ message: 'Internal server error during password verification' });
    }

    if (decryptedPassword !== currentPassword) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Update password
    const encryptedNewPassword = encryptPassword(newPassword);
    updateUser(user.id, { password: encryptedNewPassword });

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ message: 'Failed to change password' });
  }
});

app.post('/api/change-username', (req, res) => {
  const { deviceToken, newUsername, password } = req.body;

  if (!deviceToken || !newUsername || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }

  if (newUsername.length < 3) {
    return res.status(400).json({ message: 'Username must be at least 3 characters' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Verify password
    let decryptedPassword;
    try {
      decryptedPassword = decryptPassword(user.password);
    } catch (error) {
      console.error('Password decryption error:', error);
      return res.status(500).json({ message: 'Internal server error during password verification' });
    }

    if (decryptedPassword !== password) {
      return res.status(401).json({ message: 'Password is incorrect' });
    }

    // Check if new username already exists
    const existingUser = getUser(newUsername);
    if (existingUser && existingUser.id !== user.id) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    // Update username
    updateUser(user.id, { username: newUsername });

    res.json({ success: true, message: 'Username changed successfully' });
  } catch (error) {
    console.error('Error changing username:', error);
    res.status(500).json({ message: 'Failed to change username' });
  }
});

app.post('/api/delete-account', (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Delete the user
    deleteUser(user.id);

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ message: 'Failed to delete account' });
  }
});

// Music API endpoints
app.get('/api/music', (req, res) => {
  const { deviceToken } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const files = getMusicFiles(user.id);
    res.json(files);
  } catch (error) {
    console.error('Error fetching music files:', error);
    res.status(500).json({ message: 'Failed to fetch music files' });
  }
});

app.post('/api/music/upload', musicUpload.single('musicFile'), async (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'No music file provided' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Read the file to compute hash
    const fileBuffer = fs.readFileSync(req.file.path);
    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // Check if file with same hash already exists for this user
    const existingFile = getMusicFileByHash(user.id, fileHash);
    if (existingFile) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(409).json({
        message: 'File already exists',
        existingFile: existingFile
      });
    }

    // Generate/ensure GPG key for user
    const gpgKeyData = await ensureUserGPGKey(user.id);

    // Sign the file content
    const privateKey = await openpgp.readPrivateKey({ armoredKey: gpgKeyData.privateKey });
    const signature = await openpgp.sign({
      message: await openpgp.createMessage({ binary: fileBuffer }),
      signingKeys: privateKey,
      detached: true
    });

    // Move file to custommusic directory
    const filename = req.file.originalname;
    const filepath = `/assets/custommusic/${filename}`;
    let finalPath = path.join(__dirname, 'static', 'assets', 'custommusic', filename);

    // Ensure filename is unique
    let counter = 1;
    const nameParts = filename.split('.');
    const ext = nameParts.pop();
    const baseName = nameParts.join('.');
    while (fs.existsSync(finalPath)) {
      const newName = `${baseName}(${counter}).${ext}`;
      finalPath = path.join(__dirname, 'static', 'assets', 'custommusic', newName);
      filepath = `/assets/custommusic/${newName}`;
      counter++;
    }

    fs.renameSync(req.file.path, finalPath);

    // Save to database with signature
    const fileId = addMusicFile(user.id, filename, filepath, fileHash, signature);

    res.json({
      id: fileId,
      filename: filename,
      filepath: filepath,
      hash: fileHash,
      signature: signature,
      uploaded_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error uploading music file:', error);
    res.status(500).json({ message: 'Failed to upload music file' });
  }
});

app.delete('/api/music/:id', (req, res) => {
  const { id } = req.params;
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Get file info before deleting
    const files = getMusicFiles(user.id);
    const file = files.find(f => f.id === parseInt(id));
    if (!file) {
      return res.status(404).json({ message: 'Music file not found' });
    }

    // Delete from database
    deleteMusicFile(user.id, parseInt(id));

    // Delete physical file
    try {
      const fullPath = path.join(__dirname, 'static', file.filepath.substring(1)); // Remove leading /
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
      }
    } catch (fileError) {
      console.error('Error deleting physical file:', fileError);
      // Continue even if file deletion fails
    }

    res.json({ message: 'Music file deleted successfully' });
  } catch (error) {
    console.error('Error deleting music file:', error);
    res.status(500).json({ message: 'Failed to delete music file' });
  }
});

app.get('/api/music/queue', (req, res) => {
  const { deviceToken } = req.query;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    const queue = getMusicQueue(user.id);
    res.json(queue);
  } catch (error) {
    console.error('Error fetching music queue:', error);
    res.status(500).json({ message: 'Failed to fetch music queue' });
  }
});

app.post('/api/music/queue', (req, res) => {
  const { deviceToken, musicFileId, position } = req.body;

  if (!deviceToken || !musicFileId) {
    return res.status(400).json({ message: 'Device token and music file ID required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    // Check if file exists and belongs to user
    const files = getMusicFiles(user.id);
    const file = files.find(f => f.id === parseInt(musicFileId));
    if (!file) {
      return res.status(404).json({ message: 'Music file not found' });
    }

    addToQueue(user.id, parseInt(musicFileId), position);

    res.json({ message: 'Added to queue successfully' });
  } catch (error) {
    console.error('Error adding to queue:', error);
    res.status(500).json({ message: 'Failed to add to queue' });
  }
});

app.delete('/api/music/queue/:id', (req, res) => {
  const { id } = req.params;
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    removeFromQueue(user.id, parseInt(id));

    res.json({ message: 'Removed from queue successfully' });
  } catch (error) {
    console.error('Error removing from queue:', error);
    res.status(500).json({ message: 'Failed to remove from queue' });
  }
});

app.delete('/api/music/queue', (req, res) => {
  const { deviceToken } = req.body;

  if (!deviceToken) {
    return res.status(400).json({ message: 'Device token required' });
  }

  try {
    const user = getUserByDeviceToken(deviceToken);
    if (!user) {
      return res.status(401).json({ message: 'Invalid device token' });
    }

    clearMusicQueue(user.id);

    res.json({ message: 'Queue cleared successfully' });
  } catch (error) {
    console.error('Error clearing queue:', error);
    res.status(500).json({ message: 'Failed to clear queue' });
  }
});

const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/chat", file: "chat.html" },
  { path: "/ai", file: "ai.html" },
  { path: "/account", file: "account.html" },
  { path: "/metrics", file: "metrics.html" },
  { path: "/", file: "index.html" },
];

// biome-ignore lint: idk
routes.forEach(route => {
  app.get(route.path, (req, res) => {
    res.sendFile(path.join(__dirname, "static", route.file));
  });
});

app.get('/api/server-info', (req, res) => {
  // Get server IP (this might be the local IP, not the public one behind tunnel)
  const serverIP = req.socket.localAddress || req.connection.localAddress || req.socket.remoteAddress || 'unknown';
  const domain = req.headers.host;
  res.json({
    serverIP: serverIP.replace(/^::ffff:/, ''), // Remove IPv6 prefix if present
    domain: domain
  });
});

app.get('/api/version', (req, res) => {
  try {
    // Get total commit count
    const commitCount = parseInt(execSync('git rev-list --count HEAD', { encoding: 'utf8' }).trim());

    // Format version as v{major}.{minor}.{patch}
    // Major: floor(commit_count / 1000)
    // Minor: floor((commit_count % 1000) / 100)
    // Patch: commit_count % 100
    const major = Math.floor(commitCount / 1000);
    const minor = Math.floor((commitCount % 1000) / 100);
    const patch = commitCount % 100;

    const version = `v${major}.${minor}.${patch}`;
    res.json({ version, commitCount });
  } catch (error) {
    console.error('Failed to get version:', error);
    res.status(500).json({ version: 'v0.0.0', commitCount: 0 });
  }
});

app.get('/api/metrics', adminAuth, (req, res) => {
  // Prepare metrics data for the frontend
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;

  // Network traffic data (last hour)
  const networkTrafficData = {};
  for (const [domain, data] of metrics.networkTraffic) {
    const recentData = data.timestamps.map((ts, i) => ({
      timestamp: ts,
      count: data.counts[i]
    })).filter(entry => now - entry.timestamp < oneHour);
    if (recentData.length > 0) {
      networkTrafficData[domain] = recentData;
    }
  }

  // Top visited sites
  const topVisitedSites = Array.from(metrics.visitedSites.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([domain, count]) => ({ domain, count }));

  // Active sessions and time spent
  const activeSessions = Array.from(metrics.activeSessions.values());
  const timeSpentData = activeSessions.map(session => ({
    domain: session.domain || 'unknown',
    duration: now - session.startTime,
    requestCount: session.requestCount
  }));

  // Traffic history (last 24 hours)
  const trafficHistory = metrics.trafficHistory.slice(-1440); // Last 24 hours

  res.json({
    networkTraffic: networkTrafficData,
    topVisitedSites,
    timeSpent: timeSpentData,
    trafficHistory,
    activeUsers: activeSessions.length,
    totalRequests: trafficHistory.reduce((sum, entry) => sum + entry.requests, 0)
  });
});

// Warnlist API endpoints
app.get('/api/warnlist', adminAuth, (req, res) => {
  try {
    const warnlist = getWarnlist();
    res.json(warnlist);
  } catch (error) {
    console.error('Error fetching warnlist:', error);
    res.status(500).json({ message: 'Failed to fetch warnlist' });
  }
});

app.post('/api/warnlist', adminAuth, (req, res) => {
  const { domain, warning_message } = req.body;

  if (!domain) {
    return res.status(400).json({ message: 'Domain is required' });
  }

  try {
    const domainId = addDomainToWarnlist(domain, warning_message);
    res.json({ message: 'Domain added to warnlist successfully', id: domainId });
  } catch (error) {
    console.error('Error adding domain to warnlist:', error);
    res.status(500).json({ message: 'Failed to add domain to warnlist' });
  }
});

app.put('/api/warnlist/:id', adminAuth, (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    updateDomainInWarnlist(parseInt(id), updates);
    res.json({ message: 'Domain updated successfully' });
  } catch (error) {
    console.error('Error updating domain in warnlist:', error);
    res.status(500).json({ message: 'Failed to update domain' });
  }
});

app.delete('/api/warnlist/:id', adminAuth, (req, res) => {
  const { id } = req.params;

  try {
    deleteDomainFromWarnlist(parseInt(id));
    res.json({ message: 'Domain removed from warnlist successfully' });
  } catch (error) {
    console.error('Error removing domain from warnlist:', error);
    res.status(500).json({ message: 'Failed to remove domain from warnlist' });
  }
});

app.post('/api/warnlist/bulk', adminAuth, (req, res) => {
  const { action, domain_ids } = req.body;

  if (!action || !domain_ids || !Array.isArray(domain_ids)) {
    return res.status(400).json({ message: 'Action and domain_ids are required' });
  }

  try {
    bulkUpdateWarnlist(action, domain_ids);
    res.json({ message: 'Bulk operation completed successfully' });
  } catch (error) {
    console.error('Error performing bulk operation:', error);
    res.status(500).json({ message: 'Failed to perform bulk operation' });
  }
});

app.post('/api/warnlist/import', adminAuth, (req, res) => {
  const { domains } = req.body;

  if (!domains || !Array.isArray(domains)) {
    return res.status(400).json({ message: 'Domains array is required' });
  }

  try {
    const addedCount = importWarnlist(domains);
    res.json({ message: `Successfully imported ${addedCount} domains` });
  } catch (error) {
    console.error('Error importing domains:', error);
    res.status(500).json({ message: 'Failed to import domains' });
  }
});

// Domain checking middleware
app.use((req, res, next) => {
  // Only check domains for proxy requests (bare server routes)
  if (bareServer.shouldRoute(req)) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const domain = url.hostname;

    try {
      const domainCheck = isDomainWarned(domain);
      if (domainCheck.isWarned) {
        // Serve warning page
        res.setHeader('Content-Type', 'text/html');
        res.status(403).send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied</title>
            <style>
              body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: #f8f9fa;
                color: #333;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
              }
              .container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 600px;
              }
              .warning-icon {
                font-size: 48px;
                color: #dc3545;
                margin-bottom: 20px;
              }
              h1 {
                color: #dc3545;
                margin-bottom: 20px;
              }
              p {
                font-size: 16px;
                line-height: 1.6;
                margin-bottom: 30px;
              }
              .domain-name {
                font-family: monospace;
                background: #f8f9fa;
                padding: 4px 8px;
                border-radius: 4px;
                border: 1px solid #dee2e6;
                display: inline-block;
                margin: 10px 0;
              }
              .btn {
                background-color: #007bff;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                font-size: 16px;
              }
              .btn:hover {
                background-color: #0056b3;
              }
              .footer {
                margin-top: 30px;
                font-size: 12px;
                color: #6c757d;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="warning-icon">⚠️</div>
              <h1>Access Denied</h1>
              <p><strong>${domainCheck.warningMessage}</strong></p>
              <div class="domain-name">${domain}</div>
              <p>If you believe this is an error, please contact the administrator.</p>
              <a href="/" class="btn">Return to Home</a>
              <div class="footer">
                This warning was triggered by the domain filtering system.
              </div>
            </div>
          </body>
          </html>
        `);
        return;
      }
    } catch (error) {
      console.error('Error checking domain:', error);
      // Continue with request if there's an error checking the domain
    }
  }
  next();
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, "static", "404.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, "static", "404.html"));
});

server.on("request", (req, res) => {
  if (bareServer.shouldRoute(req)) {
    // Log proxy requests as potentially suspect
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
    const url = new URL(req.url, `http://${req.headers.host}`);
    logSuspectActivity(clientIP, url.hostname);

    // Collect metrics for proxy requests
    collectMetrics(clientIP, url.hostname);

    bareServer.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

// WebSocket routing
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (bareServer.shouldRoute(req)) {
    bareServer.routeUpgrade(req, socket, head);
  } else if (url.pathname === '/chat') {
    wssChat.handleUpgrade(req, socket, head, (ws) => {
      wssChat.emit('connection', ws, req);
    });
  } else if (url.pathname === '/admin/ssh-ws') {
    wssSSH.handleUpgrade(req, socket, head, (ws) => {
      wssSSH.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

server.on("listening", () => {
  console.log(chalk.green(`🌍 Server is running on http://localhost:${PORT}`));
});

// Chat state
const chatUsers = new Map(); // fingerprint -> { username, ws, isAdmin }
const chatMessages = []; // Array of messages
const bannedDevices = new Set(); // Set of banned fingerprints
let messageIdCounter = 0;

// WebSocket server for SSH
const wssSSH = new WebSocketServer({ noServer: true });

wssSSH.on('connection', (ws, req) => {
  console.log('SSH WebSocket connection established');

  let sshConn = null;

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === 'connect') {
        sshConn = new Client();

        sshConn.on('ready', () => {
          console.log('SSH connection ready');
          ws.send(JSON.stringify({ type: 'connected' }));

          sshConn.shell((err, stream) => {
            if (err) {
              ws.send(JSON.stringify({ type: 'error', message: err.message }));
              return;
            }

            stream.on('data', (data) => {
              ws.send(JSON.stringify({ type: 'data', data: data.toString() }));
            });

            stream.on('close', () => {
              ws.send(JSON.stringify({ type: 'data', data: 'SSH session closed\n' }));
              sshConn.end();
            });

            // Store stream for sending commands
            ws.sshStream = stream;
          });
        });

        sshConn.on('error', (err) => {
          console.error('SSH connection error:', err);
          ws.send(JSON.stringify({ type: 'error', message: err.message }));
        });

        sshConn.connect({
          host: message.host,
          port: message.port,
          username: message.username,
          password: message.password
        });
      } else if (message.type === 'command' && ws.sshStream) {
        ws.sshStream.write(message.command + '\n');
      }
    } catch (e) {
      console.error('WebSocket message error:', e);
    }
  });

  ws.on('close', () => {
    console.log('SSH WebSocket connection closed');
    if (sshConn) {
      sshConn.end();
    }
  });
});

// WebSocket server for Chat
const wssChat = new WebSocketServer({ noServer: true });

function broadcastToChat(message, excludeWs = null) {
  chatUsers.forEach((user, fingerprint) => {
    if (user.ws !== excludeWs && user.ws.readyState === user.ws.OPEN) {
      user.ws.send(JSON.stringify(message));
    }
  });
}

function broadcastNotification(message) {
  // Broadcast to all connected chat users
  broadcastToChat({
    type: 'notification',
    message: message.message,
    id: message.id,
    timestamp: message.created_at
  });
}

function sendUserList() {
  const users = Array.from(chatUsers.values()).map(user => ({
    username: user.username,
    fingerprint: user.fingerprint
  }));
  broadcastToChat({ type: 'userList', users });
}

wssChat.on('connection', (ws, req) => {
  console.log('Chat WebSocket connection established from:', req.url);

  let userFingerprint = '';
  let userData = null;

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === 'join') {
        userFingerprint = message.fingerprint;

        // Check if banned
        if (bannedDevices.has(userFingerprint)) {
          ws.send(JSON.stringify({ type: 'banned' }));
          ws.close();
          return;
        }

        // Check if already connected
        if (chatUsers.has(userFingerprint)) {
          ws.send(JSON.stringify({ type: 'system', message: 'Device already connected' }));
          ws.close();
          return;
        }

        // Check if admin (simplified check - in real app, verify properly)
        const isAdmin = req.url && req.url.includes('admin=true');

        userData = {
          username: message.username,
          ws: ws,
          fingerprint: userFingerprint,
          isAdmin: isAdmin
        };

        chatUsers.set(userFingerprint, userData);

        // Send recent messages (last 50)
        const recentMessages = chatMessages.slice(-50);
        recentMessages.forEach(msg => {
          ws.send(JSON.stringify({
            type: 'message',
            username: msg.username,
            message: msg.message,
            timestamp: msg.timestamp,
            image: msg.image,
            id: msg.id
          }));
        });

        // Broadcast join message
        broadcastToChat({
          type: 'system',
          message: `${message.username} joined the chat`
        });

        // Send user list
        sendUserList();

      } else if (message.type === 'message' && userData) {
        const msgId = ++messageIdCounter;
        const msgData = {
          id: msgId,
          username: userData.username,
          message: message.message,
          timestamp: new Date().toISOString(),
          image: null
        };

        chatMessages.push(msgData);
        // Keep only last 1000 messages
        if (chatMessages.length > 1000) {
          chatMessages.shift();
        }

        broadcastToChat({
          type: 'message',
          username: userData.username,
          message: message.message,
          timestamp: msgData.timestamp,
          id: msgId
        });

      } else if (message.type === 'image' && userData) {
        const msgId = ++messageIdCounter;
        const msgData = {
          id: msgId,
          username: userData.username,
          message: '',
          timestamp: new Date().toISOString(),
          image: message.image
        };

        chatMessages.push(msgData);
        if (chatMessages.length > 1000) {
          chatMessages.shift();
        }

        broadcastToChat({
          type: 'message',
          username: userData.username,
          message: '',
          timestamp: msgData.timestamp,
          image: message.image,
          id: msgId
        });

      } else if (message.type === 'delete' && userData && userData.isAdmin) {
        // Find and remove message
        const msgIndex = chatMessages.findIndex(msg => msg.id === message.messageId);
        if (msgIndex !== -1) {
          chatMessages.splice(msgIndex, 1);
          broadcastToChat({
            type: 'deleteMessage',
            messageId: message.messageId
          });
        }

      } else if (message.type === 'kick' && userData && userData.isAdmin) {
        const targetUser = chatUsers.get(message.targetFingerprint);
        if (targetUser) {
          targetUser.ws.send(JSON.stringify({ type: 'kicked' }));
          targetUser.ws.close();
          chatUsers.delete(message.targetFingerprint);
          broadcastToChat({
            type: 'system',
            message: `${targetUser.username} was kicked by ${userData.username}`
          });
          sendUserList();
        }

      } else if (message.type === 'ban' && userData && userData.isAdmin) {
        const targetUser = chatUsers.get(message.targetFingerprint);
        if (targetUser) {
          bannedDevices.add(message.targetFingerprint);
          targetUser.ws.send(JSON.stringify({ type: 'banned' }));
          targetUser.ws.close();
          chatUsers.delete(message.targetFingerprint);
          broadcastToChat({
            type: 'system',
            message: `${targetUser.username} was banned by ${userData.username}`
          });
          sendUserList();
        }
      }
    } catch (e) {
      console.error('Chat WebSocket message error:', e);
    }
  });

  ws.on('close', () => {
    console.log('Chat WebSocket connection closed');
    if (userData) {
      chatUsers.delete(userFingerprint);
      broadcastToChat({
        type: 'system',
        message: `${userData.username} left the chat`
      });
      sendUserList();
    }
  });
});

server.listen({ port: PORT });
