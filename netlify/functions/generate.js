'use strict';

// Netlify function: /.netlify/functions/generate (rewritten from /api/generate in netlify.toml)
const { generate } = require('../../lib/handler');

exports.handler = async (event) => {
  const raw = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64') : event.body || '';
  const headers = event.headers || {};

  const result = generate({
    method: event.httpMethod,
    body: raw,
    contentType: headers['content-type'] || headers['Content-Type'] || '',
  });

  const isBinary = Buffer.isBuffer(result.body);
  return {
    statusCode: result.status,
    headers: result.headers,
    body: isBinary ? result.body.toString('base64') : result.body,
    isBase64Encoded: isBinary,
  };
};
