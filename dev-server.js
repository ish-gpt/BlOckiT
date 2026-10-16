'use strict';

// Local development server: serves public/ and POST /api/generate. Not used in production.
const http = require('http');
const fs = require('fs');
const path = require('path');

try {
  process.loadEnvFile(path.join(__dirname, '.env'));
} catch {
  // no .env file — rely on the shell environment
}

const { generate } = require('./lib/handler');

const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;
const MAX_BODY = 64 * 1024;
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const filePath = path.resolve(PUBLIC_DIR, '.' + (urlPath === '/' ? '/index.html' : urlPath));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) return res.writeHead(404).end('Not found');
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(filePath)] || 'application/octet-stream' }).end(data);
  });
}

http
  .createServer((req, res) => {
    if (!req.url.startsWith('/api/generate')) return serveStatic(req, res);

    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) req.destroy();
      else chunks.push(c);
    });
    req.on('end', () => {
      const result = generate({
        method: req.method,
        body: Buffer.concat(chunks),
        contentType: req.headers['content-type'] || '',
      });
      res.writeHead(result.status, result.headers).end(result.body);
    });
  })
  .listen(PORT, () => console.log(`BlOckiT running at http://localhost:${PORT}`));
