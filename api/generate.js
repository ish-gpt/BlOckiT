'use strict';

// Vercel serverless function: POST /api/generate
const { generate } = require('../lib/handler');

module.exports = (req, res) => {
  const result = generate({
    method: req.method,
    body: req.body,
    contentType: req.headers['content-type'] || '',
  });

  res.statusCode = result.status;
  for (const [name, value] of Object.entries(result.headers)) res.setHeader(name, value);
  res.end(result.body);
};
