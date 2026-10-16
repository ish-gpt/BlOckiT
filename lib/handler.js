'use strict';

const crypto = require('crypto');
const {
  parseDomains,
  validateRemovalPassword,
  generatePermanentPassword,
  buildProfile,
  escapeXml,
  ValidationError,
} = require('./profile');
const { signProfile, ConfigError } = require('./sign');

const PROFILE_HEADERS = {
  'Content-Type': 'application/x-apple-aspen-config',
  'Content-Disposition': 'attachment; filename="blocklist.mobileconfig"',
  'Cache-Control': 'no-store',
};

/** Accepts an already-parsed object, a JSON string, or a urlencoded string. */
function parseBody(body, contentType = '') {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const raw = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw) || {};
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function errorPage(status, message) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>BlOckiT · Oops</title>
<link rel="stylesheet" href="/style.css"></head>
<body><main class="card error-page"><h1>Hmm, not quite.</h1><p>${escapeXml(message)}</p>
<a class="btn btn-back" href="/">Back</a></main></body></html>`;
  return { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, body: html };
}

/**
 * Framework-agnostic core. Returns { status, headers, body } where body is a
 * Buffer (the signed profile) or an HTML string (errors).
 */
function generate({ method, body, contentType }) {
  if (method !== 'POST') {
    const res = errorPage(405, 'Use the form on the home page to build your profile.');
    res.headers.Allow = 'POST';
    return res;
  }

  const fields = parseBody(body, contentType);

  const requiredCode = process.env.ACCESS_CODE;
  if (requiredCode && !safeEqual(fields.accessCode || '', requiredCode)) {
    return errorPage(401, 'That access code is not right.');
  }

  try {
    const domains = parseDomains(fields.domains);
    // Never log the lock password: it is only ever written into the profile.
    const locked = fields.lock === 'on';
    const permanent = locked && fields.lockMode === 'permanent';
    let removalPassword = null;
    if (permanent) {
      if (fields.permanentAck !== 'yes') {
        throw new ValidationError('Tick the box confirming only erasing your iPhone can remove a permanent lock.');
      }
      removalPassword = generatePermanentPassword();
    } else if (locked) {
      removalPassword = validateRemovalPassword(fields.lockPassword, fields.lockPasswordConfirm);
      if (!removalPassword) throw new ValidationError('Pick a lock password, or turn off Lock it.');
    }
    const signed = signProfile(buildProfile(domains, { removalPassword, permanent }));
    return { status: 200, headers: { ...PROFILE_HEADERS }, body: signed };
  } catch (err) {
    if (err instanceof ValidationError) return errorPage(400, err.message);
    if (err instanceof ConfigError) {
      console.error('[blockit] signing configuration error:', err.message);
      return errorPage(500, 'The server signing certificate is not configured correctly.');
    }
    console.error('[blockit] unexpected error:', err && err.stack);
    return errorPage(500, 'Something went wrong while building your profile.');
  }
}

module.exports = { generate, parseBody };
