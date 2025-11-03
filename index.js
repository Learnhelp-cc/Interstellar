import fs from "node:fs";
import http from "node:http";
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
const bareServer = createBareServer("/ca/");
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

server.on("upgrade", (req, socket, head) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

server.on("listening", () => {
  console.log(chalk.green(`🌍 Server is running on http://localhost:${PORT}`));
});

// WebSocket server for SSH
const wss = new WebSocketServer({ server, path: '/admin/ssh-ws' });

wss.on('connection', (ws, req) => {
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

server.listen({ port: PORT });
