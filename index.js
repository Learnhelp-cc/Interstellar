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
import Database from 'better-sqlite3';
// import { setupMasqr } from "./Masqr.js";
import config from "./config.js";
import { initDB, getUser, createUser, updateUser, getAllUsers, deleteUser, getUserByDeviceToken, updateDeviceToken, createMessage, getActiveMessages, getAllMessages, updateMessage, deleteMessage, dismissMessage, getUndismissedMessages } from "./db.js";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = path.dirname(new URL(import.meta.url).pathname);
dotenv.config({ path: path.join(__dirname, "creds.env") });

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

// Initialize database
initDB();
console.log(chalk.green("📊 Database initialized"));

// Migrate existing plain text passwords to encrypted
const migrationDb = new Database(path.join(__dirname, 'users.db'));
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
migrationDb.close();

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

    return super.createConnection(options, callback);
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

    return super.createConnection(options, callback);
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

// Create bare server with custom agents
const bareServer = createBareServer("/ca/", {
  httpAgent,
  httpsAgent,
  // Add custom request interceptor to set headers and handle cookies
  filterRemote: async (remote) => {
    // Allow all remotes for now, but we could add filtering here
  }
});

// Re-enable the V3 route handler override for Cloudflare bypass
const originalV3Handler = bareServer.routes.get('/v3/');
if (originalV3Handler) {
  console.log('Re-enabling V3 handler override with Cloudflare-friendly headers');
  bareServer.routes.set('/v3/', async (request, res, options) => {
    console.log('V3 handler called for Cloudflare bypass');

    // Get the original headers from the request
    const headers = new Headers(request.headers);
    const xBareURL = headers.get('x-bare-url');

    if (xBareURL) {
      console.log('Processing request for URL:', xBareURL);

      // Parse the x-bare-headers to modify them
      const xBareHeadersStr = headers.get('x-bare-headers');
      let bareHeaders = {};

      if (xBareHeadersStr) {
        try {
          bareHeaders = JSON.parse(xBareHeadersStr);
          console.log('Original headers:', Object.keys(bareHeaders));
        } catch (e) {
          console.log('Failed to parse x-bare-headers:', e);
          bareHeaders = {};
        }
      }

      // Add browser-like headers if not already present
      const headersToAdd = {
        'User-Agent': BROWSER_HEADERS['User-Agent'],
        'Accept': BROWSER_HEADERS['Accept'],
        'Accept-Language': BROWSER_HEADERS['Accept-Language'],
        'Accept-Encoding': BROWSER_HEADERS['Accept-Encoding'],
        'DNT': BROWSER_HEADERS['DNT'],
        'Connection': BROWSER_HEADERS['Connection'],
        'Upgrade-Insecure-Requests': BROWSER_HEADERS['Upgrade-Insecure-Requests'],
        'Sec-Fetch-Dest': BROWSER_HEADERS['Sec-Fetch-Dest'],
        'Sec-Fetch-Mode': BROWSER_HEADERS['Sec-Fetch-Mode'],
        'Sec-Fetch-Site': BROWSER_HEADERS['Sec-Fetch-Site'],
        'Sec-Fetch-User': BROWSER_HEADERS['Sec-Fetch-User'],
        'Cache-Control': BROWSER_HEADERS['Cache-Control'],
        'Sec-Ch-Ua': BROWSER_HEADERS['Sec-Ch-Ua'],
        'Sec-Ch-Ua-Mobile': BROWSER_HEADERS['Sec-Ch-Ua-Mobile'],
        'Sec-Ch-Ua-Platform': BROWSER_HEADERS['Sec-Ch-Ua-Platform']
      };

      // Discord-specific headers
      if (xBareURL.includes('discord.com') || xBareURL.includes('discordapp.com')) {
        headersToAdd['X-Super-Properties'] = 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMxLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tLyIsInJlZmVycmluZ19kb21haW4iOiJkaXNjb3JkLmNvbSIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjoxODc5NTIsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9';
        headersToAdd['X-Discord-Locale'] = 'en-US';
        headersToAdd['X-Debug-Options'] = 'bugReporterEnabled';
        headersToAdd['Authorization'] = bareHeaders['Authorization'] || '';
        headersToAdd['X-Discord-Timezone'] = 'America/New_York';
        headersToAdd['X-Context-Properties'] = 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6bnVsbCwibG9jYXRpb25fY2hhbm5lbF9pZCI6bnVsbCwibG9jYXRpb25fY2hhbm5lbF90eXBlIjpudWxsfQ==';

        // Add Origin and Referer for Discord API calls
        if (!bareHeaders['Origin'] && xBareURL.includes('/api/')) {
          headersToAdd['Origin'] = 'https://discord.com';
        }
        if (!bareHeaders['Referer']) {
          headersToAdd['Referer'] = 'https://discord.com/login';
        }

        // Additional headers for 2FA/MFA verification
        if (xBareURL.includes('/mfa/') || xBareURL.includes('/verify') || xBareURL.includes('/totp')) {
          headersToAdd['X-Fingerprint'] = bareHeaders['X-Fingerprint'] || '';
          headersToAdd['X-Captcha-Key'] = bareHeaders['X-Captcha-Key'] || '';
          headersToAdd['X-Captcha-Rqtoken'] = bareHeaders['X-Captcha-Rqtoken'] || '';
        }
      }

      for (const [key, value] of Object.entries(headersToAdd)) {
        if (!bareHeaders[key]) {
          bareHeaders[key] = value;
          console.log(`Added header: ${key}`);
        }
      }

      // Handle cookies for this domain
      const url = new URL(xBareURL);
      const domain = url.hostname;
      const existingCookies = cookieJar.get(domain);
      if (existingCookies && existingCookies.length > 0) {
        console.log('Using stored cookies for domain:', domain, existingCookies.length, 'cookies');
        if (!bareHeaders['Cookie']) {
          bareHeaders['Cookie'] = existingCookies.join('; ');
        }
      }

      // Update the x-bare-headers with our modifications
      headers.set('x-bare-headers', JSON.stringify(bareHeaders));
      console.log('Modified headers count:', Object.keys(bareHeaders).length);
    }

    // Create a new request with modified headers
    const modifiedRequest = new Request(request.url, {
      method: request.method,
      headers: headers,
      body: request.body,
      duplex: request.duplex
    });
    modifiedRequest.native = request.native;

    // Call the original handler
    const response = await originalV3Handler(modifiedRequest, res, options);

    // Extract and store cookies from the response
    if (xBareURL && response.headers.has('x-bare-headers')) {
      try {
        const responseBareHeaders = JSON.parse(response.headers.get('x-bare-headers'));
        const setCookie = responseBareHeaders['set-cookie'];
        if (setCookie) {
          const url = new URL(xBareURL);
          const domain = url.hostname;
          const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];

          if (!cookieJar.has(domain)) {
            cookieJar.set(domain, []);
          }

          const existingCookies = cookieJar.get(domain);
          for (const cookie of cookies) {
            // Simple cookie parsing - just store the cookie string
            const cookieName = cookie.split('=')[0];
            // Remove existing cookie with same name
            const filteredCookies = existingCookies.filter(c => !c.startsWith(cookieName + '='));
            filteredCookies.push(cookie);
            cookieJar.set(domain, filteredCookies);
          }
          console.log('Stored cookies for domain:', domain, cookieJar.get(domain).length, 'cookies');
        }
      } catch (e) {
        // Invalid JSON, skip cookie handling
        console.log('Failed to parse response headers for cookies');
      }
    }

    return response;
  });
} else {
  console.log('Could not find V3 handler to override');
}

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

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ message: 'Username must be at least 3 characters, password at least 6 characters' });
  }

  try {
    const encryptedPassword = encryptPassword(password);
    createUser(username, encryptedPassword);
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
  res.sendFile(path.join(__dirname, "static", "signin.html"));
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
                    <strong>Created:</strong> \${new Date(user.created_at).toLocaleString()}
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

const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/chat", file: "chat.html" },
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
  const serverIP = req.socket.localAddress || req.connection.localAddress || 'unknown';
  const domain = req.headers.host;
  res.json({
    serverIP: serverIP.replace(/^::ffff:/, ''), // Remove IPv6 prefix if present
    domain: domain
  });
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
