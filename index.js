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
// import { setupMasqr } from "./Masqr.js";
import config from "./config.js";

console.log(chalk.yellow("🚀 Starting server..."));

const __dirname = path.dirname(new URL(import.meta.url).pathname);
dotenv.config({ path: path.join(__dirname, "creds.env") });
const server = http.createServer();
const app = express();

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
    if (tracker.count >= MAX_REQUESTS_PER_WINDOW) {
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
    if (tracker.count >= MAX_REQUESTS_PER_WINDOW) {
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
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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
  'Cache-Control': 'max-age=0'
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
        'Cache-Control': BROWSER_HEADERS['Cache-Control']
      };

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
      </style>
    </head>
    <body>
      <h1>Admin Panel</h1>
      <button onclick="loadTerminal()">Load Reverse TCP Terminal</button>
      <button onclick="loadSSH()">Load SSH Terminal</button>
      <button onclick="signInAsAdmin()">Sign in as Admin (Chat)</button>
      <button onclick="viewLogs()">View Logs</button>
      <button onclick="toggleLockdown()">${isLockedDown ? 'Lift Lockdown' : 'Activate Lockdown'}</button>
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
  { path: "/", file: "index.html" },
];

// biome-ignore lint: idk
routes.forEach(route => {
  app.get(route.path, (_req, res) => {
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
