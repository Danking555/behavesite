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

// Main route - just logs display (no event logging)
app.get('/', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Behavioral Telemetry Logger</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 30px;
    }
    h3 {
      color: #ffffff;
      margin-top: 0;
    }
    .logs-container {
      background-color: #1e1e1e;
      border: 2px solid #007bff;
      border-radius: 8px;
      padding: 20px;
      max-width: 1200px;
    }
    .filter-container {
      display: flex;
      align-items: center;
      gap: 15px;
      margin-bottom: 20px;
      padding: 15px;
      background-color: #2d2d2d;
      border-radius: 6px;
      border: 1px solid #404040;
    }
    .filter-container label {
      color: #e0e0e0;
      font-weight: bold;
      margin: 0;
    }
    .filter-container select {
      background-color: #1a1a1a;
      color: #e0e0e0;
      border: 1px solid #404040;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 14px;
      min-width: 150px;
    }
    .filter-container select:focus {
      outline: none;
      border-color: #58a6ff;
      box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.2);
    }
    #logsContainer {
      background-color: #0d1117;
      padding: 15px;
      border-radius: 4px;
      min-height: 600px;
      max-height: 600px;
      overflow-y: scroll;
      font-family: 'Courier New', monospace;
      font-size: 12px;
      border: 1px solid #30363d;
      scrollbar-width: thin;
      scrollbar-color: #58a6ff #0d1117;
      position: relative;
    }
    #logsContainer::-webkit-scrollbar {
      width: 12px;
    }
    #logsContainer::-webkit-scrollbar-track {
      background: #0d1117;
      border-radius: 6px;
    }
    #logsContainer::-webkit-scrollbar-thumb {
      background: #58a6ff;
      border-radius: 6px;
      border: 2px solid #0d1117;
    }
    #logsContainer::-webkit-scrollbar-thumb:hover {
      background: #4a9eff;
    }
    #logsContainer::-webkit-scrollbar-corner {
      background: #0d1117;
    }
    button {
      background-color: #28a745;
      color: white;
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    button:hover {
      background-color: #218838;
    }
    .log-entry {
      margin: 2px 0;
      padding: 4px 8px;
      background-color: #161b22;
      border-radius: 3px;
      border-left: 3px solid #333;
    }
    .log-entry.error {
      border-left-color: #f85149;
      background-color: #2d1b1b;
    }
    .log-entry.warning {
      border-left-color: #d29922;
      background-color: #2d2a1b;
    }
    .log-entry.success {
      border-left-color: #3fb950;
      background-color: #1b2d1b;
    }
    .log-entry.debug {
      border-left-color: #6c757d;
      background-color: #1e1e1e;
    }
    .log-entry.info {
      border-left-color: #58a6ff;
      background-color: #1b2d3d;
    }
    .show-details-btn {
      background: none;
      border: none;
      color: #58a6ff;
      cursor: pointer;
      text-decoration: underline;
      margin-left: 10px;
      font-size: 12px;
    }
    .log-data {
      display: none;
      margin-top: 5px;
      padding: 10px;
      background-color: #0d1117;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      font-size: 11px;
      white-space: pre-wrap;
      max-height: 200px;
      overflow-y: auto;
      border: 1px solid #30363d;
      color: #e6edf3;
    }
  </style>
</head>
<body>
  <h1>Behavioral Telemetry Logger</h1>
  
  <!-- Logs Display Section -->
  <div class="logs-container">
    <h3>Real-time Logs</h3>
    
    <div class="filter-container">
      <label for="timeRange">Time Range:</label>
      <select id="timeRange">
        <option value="all">All Events</option>
        <option value="1h">Last Hour</option>
        <option value="6h">Last 6 Hours</option>
        <option value="24h">Last 24 Hours</option>
        <option value="7d">Last 7 Days</option>
      </select>
      <button id="refreshLogs">Refresh Logs</button>
    </div>
    
    <div id="logsContainer">
      <div>Loading logs...</div>
    </div>
  </div>

  <script>
  // Logs Display Script (No Event Logging)
  (function() {
    function loadLogs() {
      const timeRange = document.getElementById('timeRange').value;
      let url = '/api/logs?limit=10000';
      
      // Add time range filter if not "all"
      if (timeRange !== 'all') {
        const now = new Date();
        let startTime;
        
        switch (timeRange) {
          case '1h':
            startTime = new Date(now.getTime() - 60 * 60 * 1000);
            break;
          case '6h':
            startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
            break;
          case '24h':
            startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
            break;
          case '7d':
            startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
            break;
        }
        
        if (startTime) {
          url += '&startTime=' + startTime.toISOString();
        }
      }
      
      fetch(url)
        .then(response => response.json())
        .then(logs => {
          const logsContainer = document.getElementById('logsContainer');
          logsContainer.innerHTML = '';
          
          logs.forEach(log => {
            const logEntry = document.createElement('div');
            const timestamp = new Date(log.timestamp).toLocaleTimeString();
            
            // Parse the log body to extract message and data
            let logData = null;
            let message = log.method + ' ' + log.url;
            
            try {
              const bodyData = JSON.parse(log.body);
              if (bodyData.message) {
                message = bodyData.message;
              }
              if (bodyData.data) {
                logData = bodyData.data;
              }
            } catch (e) {
              // If parsing fails, use the raw body
              message = log.body || message;
            }
            
            // Determine log type from method or message
            let type = 'info';
            if (log.method === 'CLIENT_LOG') {
              try {
                const bodyData = JSON.parse(log.body);
                type = bodyData.type || 'info';
                message = bodyData.message || message;
                logData = bodyData.data || logData;
              } catch (e) {
                type = 'info';
              }
            }
            
            // Check if this is a debug log with detailed data (even if not marked as CLIENT_LOG)
            if (!logData && log.body) {
              try {
                const bodyData = JSON.parse(log.body);
                if (bodyData.message && (bodyData.message.includes('Full') || bodyData.message.includes('event data'))) {
                  type = 'debug';
                  message = bodyData.message;
                  logData = bodyData.data;
                }
              } catch (e) {
                // Try to detect debug logs by message content
                if (log.body.includes('Full') && log.body.includes('event data')) {
                  type = 'debug';
                  message = log.body;
                }
              }
            }
            
            // Add CSS class based on log type
            logEntry.className = 'log-entry ' + type;
            
            let displayMessage = '[' + timestamp + '] [' + type.toUpperCase() + '] ' + message;
            
            if (logData && type === 'debug') {
              // Create expandable section for debug logs
              const showDetailsBtn = document.createElement('button');
              showDetailsBtn.textContent = '[Show Details]';
              showDetailsBtn.className = 'show-details-btn';
              
              const dataDiv = document.createElement('div');
              dataDiv.className = 'log-data';
              dataDiv.style.display = 'none';
              dataDiv.textContent = JSON.stringify(logData, null, 2);
              
              showDetailsBtn.addEventListener('click', function() {
                if (dataDiv.style.display === 'none') {
                  dataDiv.style.display = 'block';
                  showDetailsBtn.textContent = '[Hide Details]';
                } else {
                  dataDiv.style.display = 'none';
                  showDetailsBtn.textContent = '[Show Details]';
                }
              });
              
              logEntry.innerHTML = displayMessage;
              logEntry.appendChild(showDetailsBtn);
              logEntry.appendChild(dataDiv);
            } else if (message.includes('Full') && message.includes('event data')) {
              // Handle logs that have detailed data but weren't parsed correctly
              const showDetailsBtn = document.createElement('button');
              showDetailsBtn.textContent = '[Show Details]';
              showDetailsBtn.className = 'show-details-btn';
              
              const dataDiv = document.createElement('div');
              dataDiv.className = 'log-data';
              dataDiv.style.display = 'none';
              dataDiv.textContent = log.body || 'No detailed data available';
              
              showDetailsBtn.addEventListener('click', function() {
                if (dataDiv.style.display === 'none') {
                  dataDiv.style.display = 'block';
                  showDetailsBtn.textContent = '[Hide Details]';
                } else {
                  dataDiv.style.display = 'none';
                  showDetailsBtn.textContent = '[Show Details]';
                }
              });
              
              logEntry.innerHTML = displayMessage;
              logEntry.appendChild(showDetailsBtn);
              logEntry.appendChild(dataDiv);
            } else {
              logEntry.innerHTML = displayMessage;
            }
            
            logsContainer.appendChild(logEntry);
          });
        })
        .catch(err => {
          console.error('Failed to load logs:', err);
          document.getElementById('logsContainer').innerHTML = '<div style="color: #f85149;">Failed to load logs</div>';
        });
    }
    
    // Load logs on page load
    document.addEventListener('DOMContentLoaded', loadLogs);
    
    // Refresh logs button
    document.getElementById('refreshLogs').addEventListener('click', loadLogs);
    
    // Time range selector
    document.getElementById('timeRange').addEventListener('change', loadLogs);
  })();
  </script>
</body>
</html>`;
  
  res.send(html);
});

// Login route with bot detection
app.get('/login', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login - Behavioral Telemetry Logger</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 30px;
    }
    h3 {
      color: #ffffff;
      margin-top: 0;
    }
    .container {
      background-color: #2d2d2d;
      border: 2px solid #404040;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
    }
    .navigation-container {
      background-color: #2d2d2d;
      border: 2px solid #6c757d;
      border-radius: 8px;
      padding: 20px;
      max-width: 400px;
    }
    .login-container {
      background-color: #2d2d2d;
      border: 2px solid #404040;
      border-radius: 8px;
      padding: 20px;
      max-width: 400px;
    }
    form {
      margin: 0;
    }
    label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
      color: #ffffff;
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 8px;
      border: 1px solid #404040;
      border-radius: 4px;
      box-sizing: border-box;
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-size: 14px;
    }
    input[type="text"]:focus, input[type="password"]:focus {
      outline: none;
      border-color: #58a6ff;
      box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.2);
    }
    button {
      background-color: #007bff;
      color: white;
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover {
      background-color: #0056b3;
    }
    a {
      color: #58a6ff;
      text-decoration: none;
      font-weight: bold;
    }
    a:hover {
      text-decoration: underline;
    }
    #loginStatus {
      margin-top: 10px;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <h1>Login Form</h1>
  
  <div class="navigation-container">
    <h3>Navigation</h3>
    <p>Go back to <a href="/">main page</a> to view logs.</p>
  </div>
  
  <!-- Login Form with Bot Detection -->
  <div class="login-container">
    <h3>Login Form</h3>
    <form id="loginForm">
      <div style="margin-bottom: 15px;">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" placeholder="Enter username">
      </div>
      <div style="margin-bottom: 15px;">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" placeholder="Enter password">
      </div>
      <button type="submit" id="loginBtn">
        Login
      </button>
      <div id="loginStatus"></div>
    </form>
  </div>

  <script>
  // Bot Detection Script
  (function() {
    // Logging functions
    function logToPage(message, type = 'info', data = null) {
      // For login page, we'll just log to console since there's no logs display
      console.log('[' + type.toUpperCase() + '] ' + message, data);
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
      
      // Log to page (console only for login page)
      logToPage(message, type, data);
      
      // Log to database
      logToDatabase(type, message, data);
    }
    
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
      console.log('KEYBOARD EVENT DETECTED:', event.type, event.key, event.code);
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
    
    // Track keyboard events on ALL elements
    document.addEventListener("keydown", trackKey);
    document.addEventListener("keyup", trackKey);
    document.addEventListener("keypress", trackKey);
    
    // Track ALL mouse events with synthetic detection
    document.addEventListener("mousedown", (e) => {
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
      logEverywhere("info", "Mouse down at (" + e.clientX + ", " + e.clientY + ") on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full mouse down event data", eventData);
    });

    document.addEventListener("mouseup", (e) => {
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
      logEverywhere("info", "Mouse up at (" + e.clientX + ", " + e.clientY + ") on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full mouse up event data", eventData);
    });

    document.addEventListener("mousemove", (e) => {
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
      logEverywhere("info", "Mouse move at (" + e.clientX + ", " + e.clientY + ") on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full mouse move event data", eventData);
    });

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

    // Track scroll events
    document.addEventListener("scroll", (e) => {
      const syntheticInfo = isSyntheticEvent(e);
      const eventData = {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
        scrollX: window.scrollX,
        scrollY: window.scrollY,
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
          isTrusted: e.isTrusted
        }
      };
      
      logEverywhere("info", "Scroll event on " + (e.target.id || e.target.tagName) + " at (" + window.scrollX + ", " + window.scrollY + ")");
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full scroll event data", eventData);
    });

    // Track focus events
    document.addEventListener("focus", (e) => {
      const syntheticInfo = isSyntheticEvent(e);
      const eventData = {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
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
      
      logEverywhere("info", "Focus event on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full focus event data", eventData);
    });

    // Track blur events
    document.addEventListener("blur", (e) => {
      const syntheticInfo = isSyntheticEvent(e);
      const eventData = {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
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
      
      logEverywhere("info", "Blur event on " + (e.target.id || e.target.tagName));
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full blur event data", eventData);
    });

    // Track touch events (for mobile devices)
    document.addEventListener("touchstart", (e) => {
      const syntheticInfo = isSyntheticEvent(e);
      const eventData = {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
        touches: e.touches.length,
        changedTouches: e.changedTouches.length,
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
          isTrusted: e.isTrusted
        }
      };
      
      logEverywhere("info", "Touch start on " + (e.target.id || e.target.tagName) + " (" + e.touches.length + " touches)");
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full touch start event data", eventData);
    });

    document.addEventListener("touchend", (e) => {
      const syntheticInfo = isSyntheticEvent(e);
      const eventData = {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
        touches: e.touches.length,
        changedTouches: e.changedTouches.length,
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
          isTrusted: e.isTrusted
        }
      };
      
      logEverywhere("info", "Touch end on " + (e.target.id || e.target.tagName) + " (" + e.changedTouches.length + " changed touches)");
      logEverywhere("info", "Synthetic: " + syntheticInfo.isSynthetic + ", Trust: " + syntheticInfo.trustLevel);
      logEverywhere("debug", "Full touch end event data", eventData);
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
  const limit = req.query.limit ? parseInt(req.query.limit) : null;
  const startTime = req.query.startTime;
  
  let query = `SELECT * FROM logs`;
  let params = [];
  
  // Add time filter if startTime is provided
  if (startTime) {
    query += ` WHERE timestamp >= ?`;
    params.push(startTime);
  }
  
  query += ` ORDER BY timestamp DESC`;
  
  // Add limit only if specified
  if (limit) {
    query += ` LIMIT ?`;
    params.push(limit);
  }
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Error fetching logs:', err);
      res.status(500).json({ error: 'Failed to fetch logs' });
    } else {
      res.json(rows);
    }
  });
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