/**
 * Simplified HTTP Request Logger with Bot Detection
 * 
 * Minimal Express.js app that serves only "/" with bot detection on login form.
 * Logs HTTP requests to SQLite and includes WebSocket fingerprinting.
 * 
 * Setup:
 *   npm init -y
 *   npm install express sqlite3 ws
 *   node index.js
 */

const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;

// JSON parsing
app.use(express.json());

// Initialize SQLite database
const dbPath = path.join(os.tmpdir(), 'logs.db');
const db = new sqlite3.Database(dbPath, err => {
  if (err) console.error('DB connection error:', err.message);
  else console.log(`Connected to SQLite DB at ${dbPath}`);
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT,
      url TEXT,
      headers TEXT,
      body TEXT,
      timestamp TEXT
    )
  `);
});

// Middleware: log every HTTP request
app.use((req, res, next) => {
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const headersStr = JSON.stringify(headers);
  const bodyStr = body && Object.keys(body).length ? JSON.stringify(body) : '';
  db.run(
    `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
    [method, url, headersStr, bodyStr, timestamp]
  );
  next();
});

// Main route with bot detection
app.get('/', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Behavioral Telemetry Logger</title>
</head>
<body>
  <h1>Behavioral Telemetry Logger</h1>
  
  <!-- Logs Display Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #007bff; border-radius: 8px; max-width: 800px;">
    <h3>Real-time Logs</h3>
    <div id="logsContainer" style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 12px;">
      <div>Loading logs...</div>
    </div>
    <button id="refreshLogs" style="margin-top: 10px; background-color: #28a745; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer;">
      Refresh Logs
    </button>
  </div>
  
  <!-- Login Form with Bot Detection -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #ccc; border-radius: 8px; max-width: 400px;">
    <h3>Login Form</h3>
    <form id="loginForm">
      <div style="margin-bottom: 15px;">
        <label for="username" style="display: block; margin-bottom: 5px; font-weight: bold;">Username:</label>
        <input type="text" id="username" name="username" placeholder="Enter username" 
               style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
      </div>
      <div style="margin-bottom: 15px;">
        <label for="password" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
        <input type="password" id="password" name="password" placeholder="Enter password" 
               style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
      </div>
      <button type="submit" id="loginBtn" 
              style="background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">
        Login
      </button>
      <div id="loginStatus" style="margin-top: 10px; font-weight: bold;"></div>
    </form>
  </div>

  <script>
  // Bot Detection Script
  (function() {
    // Logging functions
    function logToPage(message, type = 'info', data = null) {
      const logsContainer = document.getElementById('logsContainer');
      const timestamp = new Date().toLocaleTimeString();
      const logEntry = document.createElement('div');
      logEntry.style.marginBottom = '5px';
      logEntry.style.padding = '3px 6px';
      logEntry.style.borderRadius = '3px';
      
      // Color coding based on type
      switch(type) {
        case 'error':
          logEntry.style.backgroundColor = '#f8d7da';
          logEntry.style.color = '#721c24';
          break;
        case 'warning':
          logEntry.style.backgroundColor = '#fff3cd';
          logEntry.style.color = '#856404';
          break;
        case 'success':
          logEntry.style.backgroundColor = '#d4edda';
          logEntry.style.color = '#155724';
          break;
        case 'debug':
          logEntry.style.backgroundColor = '#e2e3e5';
          logEntry.style.color = '#383d41';
          break;
        default:
          logEntry.style.backgroundColor = '#d1ecf1';
          logEntry.style.color = '#0c5460';
      }
      
      let displayMessage = '[' + timestamp + '] [' + type.toUpperCase() + '] ' + message;
      
      // Add expandable data section for debug logs
      if (data && type === 'debug') {
        const dataId = 'data-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        const toggleButton = document.createElement('span');
        toggleButton.innerHTML = ' [Show Details]';
        toggleButton.style.cursor = 'pointer';
        toggleButton.style.color = '#007bff';
        toggleButton.style.textDecoration = 'underline';
        
        const dataDiv = document.createElement('div');
        dataDiv.id = dataId;
        dataDiv.style.display = 'none';
        dataDiv.style.marginTop = '5px';
        dataDiv.style.padding = '5px';
        dataDiv.style.backgroundColor = '#f8f9fa';
        dataDiv.style.border = '1px solid #dee2e6';
        dataDiv.style.borderRadius = '3px';
        dataDiv.style.fontSize = '10px';
        dataDiv.style.whiteSpace = 'pre-wrap';
        dataDiv.innerHTML = JSON.stringify(data, null, 2);
        
        toggleButton.onclick = function() {
          if (dataDiv.style.display === 'none') {
            dataDiv.style.display = 'block';
            toggleButton.innerHTML = ' [Hide Details]';
          } else {
            dataDiv.style.display = 'none';
            toggleButton.innerHTML = ' [Show Details]';
          }
        };
        
        logEntry.appendChild(document.createTextNode(displayMessage));
        logEntry.appendChild(toggleButton);
        logEntry.appendChild(dataDiv);
      } else {
        logEntry.innerHTML = displayMessage;
      }
      
      logsContainer.insertBefore(logEntry, logsContainer.firstChild);
      
      // Keep only last 100 log entries
      while (logsContainer.children.length > 100) {
        logsContainer.removeChild(logsContainer.lastChild);
      }
    }
    
    function logToDatabase(type, message, data = null) {
      fetch('/api/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type,
          message,
          data,
          timestamp: new Date().toISOString()
        })
      }).catch(err => console.error('Failed to log to database:', err));
    }
    
    function logEverywhere(type, message, data = null) {
      // Log to console (existing behavior)
      console.log('[' + type + '] ' + message, data);
      
      // Log to page
      logToPage(message, type, data);
      
      // Log to database
      logToDatabase(type, message, data);
    }
    
    function loadLogs() {
      fetch('/api/logs?limit=20')
        .then(response => response.json())
        .then(logs => {
          const logsContainer = document.getElementById('logsContainer');
          logsContainer.innerHTML = '';
          
          if (logs.length === 0) {
            logsContainer.innerHTML = '<div>No logs available</div>';
            return;
          }
          
          logs.forEach(log => {
            const logEntry = document.createElement('div');
            logEntry.style.marginBottom = '5px';
            logEntry.style.padding = '3px 6px';
            logEntry.style.borderRadius = '3px';
            logEntry.style.backgroundColor = '#e9ecef';
            logEntry.style.color = '#495057';
            
            const timestamp = new Date(log.timestamp).toLocaleString();
            const method = log.method || 'UNKNOWN';
            const url = log.url || 'N/A';
            
            logEntry.innerHTML = '[' + timestamp + '] [' + method + '] ' + url;
            if (log.body) {
              try {
                const bodyData = JSON.parse(log.body);
                if (bodyData.message) {
                  logEntry.innerHTML += ' - ' + bodyData.message;
                }
              } catch (e) {
                // Ignore JSON parse errors for non-JSON body content
              }
            }
            
            logsContainer.appendChild(logEntry);
          });
        })
        .catch(err => {
          console.error('Failed to load logs:', err);
          document.getElementById('logsContainer').innerHTML = '<div style="color: red;">Failed to load logs</div>';
        });
    }
    
    // Set up refresh button
    document.addEventListener('DOMContentLoaded', () => {
      const refreshBtn = document.getElementById('refreshLogs');
      if (refreshBtn) {
        refreshBtn.addEventListener('click', loadLogs);
      }
      // Load initial logs
      loadLogs();
    });
    const username = document.getElementById("username");
    const password = document.getElementById("password");
    const loginBtn = document.getElementById("loginBtn");
    const form = document.getElementById("loginForm");
    
    let userTyped = false;
    let userClicked = false;
    const keyEvents = []; // Store key press events
    const clickEvents = []; // Store mouse click events
    
    // Function to detect synthetic events
    function isSyntheticEvent(event) {
      const synthetic = {
        isTrusted: event.isTrusted === false, // false means synthetic
        detail: event.detail === 0, // 0 often indicates synthetic
        timeStamp: event.timeStamp === 0, // 0 often indicates synthetic
        bubbles: event.bubbles === false, // some synthetic events don't bubble
        cancelable: event.cancelable === false, // some synthetic events aren't cancelable
        eventPhase: event.eventPhase === 0, // 0 = none phase
        hasPointerCoords: event.clientX === 0 && event.clientY === 0, // synthetic mouse events often at 0,0
        hasKeyData: event.key === undefined || event.code === undefined // synthetic key events may lack data
      };
      
      return {
        isSynthetic: !event.isTrusted || event.detail === 0 || event.timeStamp === 0,
        syntheticFlags: synthetic,
        confidence: Object.values(synthetic).filter(Boolean).length,
        trustLevel: event.isTrusted ? 'trusted' : 'untrusted'
      };
    }
    
    // Track key presses with timestamp and synthetic detection
    function trackKey(event) {
      userTyped = true;
      const syntheticInfo = isSyntheticEvent(event);
      
      // Create comprehensive event data
      const eventData = {
        key: event.key,
        code: event.code,
        keyCode: event.keyCode,
        which: event.which,
        timestamp: Date.now(),
        isTrusted: event.isTrusted,
        synthetic: syntheticInfo,
        target: event.target.id || event.target.tagName,
        // Additional key-specific properties
        altKey: event.altKey,
        ctrlKey: event.ctrlKey,
        shiftKey: event.shiftKey,
        metaKey: event.metaKey,
        repeat: event.repeat,
        location: event.location,
        // Full event object for debugging
        fullEvent: {
          type: event.type,
          bubbles: event.bubbles,
          cancelable: event.cancelable,
          defaultPrevented: event.defaultPrevented,
          eventPhase: event.eventPhase,
          timeStamp: event.timeStamp,
          detail: event.detail,
          view: event.view ? 'window' : 'null',
          currentTarget: event.currentTarget ? event.currentTarget.tagName : 'null',
          target: event.target ? event.target.tagName : 'null',
          srcElement: event.srcElement ? event.srcElement.tagName : 'null',
          returnValue: event.returnValue,
          cancelBubble: event.cancelBubble,
          composed: event.composed,
          isTrusted: event.isTrusted
        }
      };
      
      keyEvents.push(eventData);
      
      // Log comprehensive event information
      logEverywhere("info", "Keyboard event: " + event.key + " (" + event.code + ") at " + new Date().toISOString());
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full keyboard event data", eventData);
    }
    
    username.addEventListener("keydown", trackKey);
    password.addEventListener("keydown", trackKey);
    
    // Track mouse clicks with synthetic detection
    document.addEventListener("click", (e) => {
      userClicked = true;
      const syntheticInfo = isSyntheticEvent(e);
      
      // Create comprehensive event data
      const eventData = {
        x: e.clientX,
        y: e.clientY,
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        button: e.button,
        buttons: e.buttons,
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
        detail: e.detail,
        eventPhase: e.eventPhase,
        // Additional mouse-specific properties
        screenX: e.screenX,
        screenY: e.screenY,
        pageX: e.pageX,
        pageY: e.pageY,
        offsetX: e.offsetX,
        offsetY: e.offsetY,
        movementX: e.movementX,
        movementY: e.movementY,
        altKey: e.altKey,
        ctrlKey: e.ctrlKey,
        shiftKey: e.shiftKey,
        metaKey: e.metaKey,
        // Full event object for debugging
        fullEvent: {
          type: e.type,
          bubbles: e.bubbles,
          cancelable: e.cancelable,
          defaultPrevented: e.defaultPrevented,
          eventPhase: e.eventPhase,
          timeStamp: e.timeStamp,
          detail: e.detail,
          view: e.view ? 'window' : 'null',
          currentTarget: e.currentTarget ? e.currentTarget.tagName : 'null',
          target: e.target ? e.target.tagName : 'null',
          srcElement: e.srcElement ? e.srcElement.tagName : 'null',
          returnValue: e.returnValue,
          cancelBubble: e.cancelBubble,
          composed: e.composed,
          isTrusted: e.isTrusted,
          relatedTarget: e.relatedTarget ? e.relatedTarget.tagName : 'null'
        }
      };
      
      clickEvents.push(eventData);
      
      // Log comprehensive event information
      logEverywhere("info", "Mouse click at (" + e.clientX + ", " + e.clientY + ") on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full mouse click event data", eventData);
    });
    
    // On form submit, check behavior
    form.addEventListener("submit", (e) => {
      e.preventDefault(); // Always prevent default for demo
      
      if (!userTyped || !userClicked) {
        alert("⚠️ Possible bot detected: no real typing or clicking.");
        logEverywhere("warning", "Bot-like behavior detected - no real typing or clicking");
        document.getElementById("loginStatus").innerHTML = 
          '<span style="color: red;">Bot detected - Login blocked</span>';
      } else {
        logEverywhere("success", "User likely human - login successful");
        logEverywhere("info", "Key events captured: " + keyEvents.length, keyEvents);
        logEverywhere("info", "Click events captured: " + clickEvents.length, clickEvents);
        document.getElementById("loginStatus").innerHTML = 
          '<span style="color: green;">Human verified - Login successful</span>';
        
        // Send detection data via WebSocket
        sendDetectionData({
          humanVerified: true,
          keyEvents: keyEvents,
          clickEvents: clickEvents
        });
      }
    });
    
    // Fingerprinting functions
    function getCanvasFingerprint() {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('FPJS', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('FPJS', 4, 17);
      return canvas.toDataURL();
    }
    
    // Send fingerprint and detection data
    function sendDetectionData(detectionData) {
      const fp = {
        origin: location.pathname,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages,
        screen: {
          width: screen.width,
          height: screen.height,
          colorDepth: screen.colorDepth
        },
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        webdriver: navigator.webdriver || false,
        pluginsCount: navigator.plugins.length,
        canvas: getCanvasFingerprint(),
        botDetection: detectionData,
        timestamp: new Date().toISOString()
      };
      
      // Send via WebSocket
      const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'fingerprint', data: fp }));
        ws.close();
      };
    }
    
    // Send initial fingerprint on page load
    window.addEventListener('load', () => {
      setTimeout(() => {
        sendDetectionData({
          humanVerified: false,
          keyEvents: [],
          clickEvents: [],
          pageLoad: true
        });
      }, 1000);
    });
  })();
  </script>
</body>
</html>`;
  
  res.send(html);
});

// API endpoint to fetch recent logs
app.get('/api/logs', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  db.all(
    `SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?`,
    [limit],
    (err, rows) => {
      if (err) {
        console.error('Error fetching logs:', err);
        res.status(500).json({ error: 'Failed to fetch logs' });
      } else {
        res.json(rows);
      }
    }
  );
});

// API endpoint to receive client-side logs
app.post('/api/logs', (req, res) => {
  const { type, message, data, timestamp } = req.body;
  const logMessage = `[${type}] ${message}`;
  const logData = JSON.stringify({ message, data, timestamp });
  
  // Log to database
  db.run(
    `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
    ['CLIENT_LOG', '/api/logs', '{}', logData, timestamp || new Date().toISOString()]
  );
  
  // Log to console
  console.log(logMessage, data);
  
  res.json({ success: true });
});

// WebSocket server for fingerprint messages
const wss = new WebSocket.Server({ server });
wss.on('connection', ws => {
  ws.on('message', message => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'fingerprint') {
        const { origin, ...data } = msg.data;
        const ts = new Date().toISOString();
        db.run(
          `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
          ['WS', origin, '{}', JSON.stringify(data), ts]
        );
        console.log('Fingerprint received:', {
          origin,
          botDetection: data.botDetection,
          timestamp: ts
        });
        console.log('[FINGERPRINT] Received from ' + origin + ' - Bot Detection: ' + (data.botDetection && data.botDetection.humanVerified ? 'Human' : 'Unknown'));
      }
    } catch (e) {
      console.error('WS parse error:', e);
    }
  });
});

// Start server
server.listen(port, () => console.log(`Server running on http://localhost:${port}`));