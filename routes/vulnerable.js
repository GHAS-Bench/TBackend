const crypto = require('crypto');
const vm = require('vm');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const express = require('express');
const axios = require('axios');
const _ = require('lodash');
const serialize = require('serialize-javascript');

const router = express.Router();

// Simulated DB — string concatenation triggers CodeQL sql-injection rules
function runQuery(sql) {
  return { sql, rows: [] };
}

// SQL injection: user input concatenated into query
router.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  const result = runQuery(query);
  res.json({ query: result.sql, users: result.rows });
});

router.post('/users/search', (req, res) => {
  const name = req.body.name || req.query.name || '';
  const query = `SELECT * FROM users WHERE name LIKE '%${name}%'`;
  res.json({ query, users: runQuery(query).rows });
});

// Command injection: user input passed to exec
router.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr || err.message });
    }
    res.json({ output: stdout });
  });
});

router.post('/run', (req, res) => {
  const cmd = req.body.command;
  exec(cmd, (err, stdout, stderr) => {
    res.json({ stdout, stderr, error: err ? err.message : null });
  });
});

// Path traversal: user-supplied path read from filesystem
router.get('/file', (req, res) => {
  const filePath = req.query.path;
  const content = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(content);
});

router.get('/download', (req, res) => {
  const filename = req.query.name;
  const fullPath = path.join('/uploads', filename);
  const data = fs.readFileSync(fullPath);
  res.send(data);
});

// Reflected XSS: unsanitized user input in HTML response
router.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

// Unsafe deserialization via eval on serialized payload
router.post('/deserialize', (req, res) => {
  const payload = req.body.data;
  const parsed = eval('(' + payload + ')');
  res.json({ result: parsed });
});

router.post('/restore-state', (req, res) => {
  const state = req.body.state;
  const restored = eval('(' + serialize(state) + ')');
  res.json({ restored });
});

// Weak crypto: MD5 for password hashing, Math.random for tokens
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  const sessionToken = Math.random().toString(36).slice(2);
  res.json({ username, hash, sessionToken });
});

router.get('/token', (req, res) => {
  const token = Math.floor(Math.random() * 1e16).toString(16);
  res.json({ token });
});

// SSRF: user-controlled URL passed to server-side HTTP client
router.get('/proxy', async (req, res) => {
  const targetUrl = req.query.url;
  try {
    const response = await axios.get(targetUrl);
    res.json({
      url: targetUrl,
      status: response.status,
      headers: response.headers,
      data: response.data,
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Prototype pollution via lodash merge (also exercises vulnerable dep)
router.post('/merge-config', (req, res) => {
  const defaults = { settings: { debug: false } };
  const merged = _.merge(defaults, req.body);
  res.json(merged);
});

// Code injection fixed: do not execute user-provided script
router.post('/execute', (req, res) => {
  const script = req.body.script || req.query.script;
  res.status(400).json({
    error: 'Executing user-provided scripts is not allowed.',
    script: script || null
  });
});

// Log injection: sanitize user input before writing to application logs
router.get('/audit-log', (req, res) => {
  const event = req.query.event || 'unknown';
  const sanitizedEvent = String(event).replace(/[\r\n]/g, '');
  console.log('[AUDIT] user event: ' + sanitizedEvent);
  res.json({ logged: true, event });
});

module.exports = router;
