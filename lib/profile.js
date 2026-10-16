'use strict';

const crypto = require('crypto');
const { domainToASCII } = require('url');

const MAX_DOMAINS = 500;
const MAX_INPUT_CHARS = 20000;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Turn whatever the user typed ("https://www.YouTube.com/watch?v=1", "*.reddit.com")
 * into a bare, punycoded hostname, or null if it isn't a valid domain.
 */
function normaliseDomain(raw) {
  let s = String(raw).trim().toLowerCase();
  if (!s) return null;

  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  s = s.split(/[/?#]/)[0]; // path, query, fragment
  s = s.replace(/^[^@]*@/, ''); // userinfo
  s = s.replace(/:\d+$/, ''); // port
  s = s.replace(/^\*\./, '').replace(/\.$/, ''); // wildcard prefix, trailing dot

  const ascii = domainToASCII(s);
  if (!ascii || ascii.length > 253) return null;

  const labels = ascii.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return null; // IP addresses / numeric TLDs

  return ascii;
}

/**
 * Accepts a newline/comma/space separated string (or an array) and returns
 * de-duplicated valid domains plus the entries that were rejected.
 */
function parseDomains(input) {
  if (Array.isArray(input)) input = input.join('\n');
  if (typeof input !== 'string') input = '';

  if (input.length > MAX_INPUT_CHARS) {
    throw new ValidationError(`That list is too long (max ${MAX_INPUT_CHARS} characters).`);
  }

  const domains = new Set();
  const invalid = [];

  for (const entry of input.split(/[\s,]+/)) {
    if (!entry) continue;
    const d = normaliseDomain(entry);
    if (d) domains.add(d);
    else invalid.push(entry);
  }

  if (invalid.length) {
    const sample = invalid.slice(0, 5).join(', ');
    throw new ValidationError(`These don't look like domains: ${sample}${invalid.length > 5 ? '…' : ''}`);
  }
  if (domains.size === 0) throw new ValidationError('Add at least one domain to block.');
  if (domains.size > MAX_DOMAINS) throw new ValidationError(`Too many domains (max ${MAX_DOMAINS}).`);

  return [...domains];
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Each domain is blocked at its apex and www host, whichever form was typed. */
function domainsToUrls(domains) {
  const urls = new Set();
  for (const d of domains) {
    const apex = d.startsWith('www.') && d.split('.').length > 2 ? d.slice(4) : d;
    urls.add(`https://${apex}`);
    urls.add(`https://www.${apex}`);
  }
  return [...urls];
}

// Fixed identifiers: installing a new BlOckiT profile replaces the old one instead of adding another.
const PROFILE_ID = 'com.blockit.profile';
const CONTENT_FILTER_UUID = '6E0C5A3B-2F4D-4B8E-9C1A-B10C4171F11E'; // required on unsupervised devices

const MIN_PASSWORD = 6;
const MAX_PASSWORD = 128;

/** Returns the password unchanged, or null when locking is off. Throws on invalid input. */
function validateRemovalPassword(password, confirm) {
  if (password === undefined || password === null || password === '') return null;
  if (typeof password !== 'string') throw new ValidationError('The lock password is not valid.');
  if (password.length < MIN_PASSWORD) {
    throw new ValidationError(`Make the lock password at least ${MIN_PASSWORD} characters.`);
  }
  if (password.length > MAX_PASSWORD) {
    throw new ValidationError(`Keep the lock password under ${MAX_PASSWORD} characters.`);
  }
  if (/[\u0000-\u001f\u007f]/.test(password)) {
    throw new ValidationError('The lock password contains characters iOS cannot accept.');
  }
  if (confirm !== undefined && confirm !== password) {
    throw new ValidationError("The two lock passwords don't match.");
  }
  return password;
}

/**
 * A random password that is written into the profile and then forgotten: it is never
 * returned, logged or stored, so only erasing the iPhone removes a permanent profile.
 */
function generatePermanentPassword() {
  return crypto.randomBytes(32).toString('base64url');
}

function removalPasswordPayload(password, identifier) {
  return `
        <dict>
            <key>PayloadDisplayName</key>
            <string>Removal Password</string>
            <key>PayloadIdentifier</key>
            <string>${identifier}</string>
            <key>PayloadType</key>
            <string>com.apple.profileRemovalPassword</string>
            <key>PayloadUUID</key>
            <string>${crypto.randomUUID().toUpperCase()}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>RemovalPassword</key>
            <string>${escapeXml(password)}</string>
        </dict>`;
}

function buildProfile(domains, { removalPassword = null, permanent = false } = {}) {
  const filterUuid = crypto.randomUUID().toUpperCase();
  const profileUuid = crypto.randomUUID().toUpperCase();
  // A permanent profile gets a one-off identifier so no later profile can replace (and unlock) it.
  const profileId = permanent ? `${PROFILE_ID}.permanent.${profileUuid}` : PROFILE_ID;
  const contentFilterUuid = permanent ? crypto.randomUUID().toUpperCase() : CONTENT_FILTER_UUID;
  const urlItems = domainsToUrls(domains)
    .map((u) => `                <string>${escapeXml(u)}</string>`)
    .join('\n');
  const lockPayload = removalPassword ? removalPasswordPayload(removalPassword, `${profileId}.removalpassword`) : '';
  const displayName = permanent
    ? 'BlOckiT Website Blocker (Permanent)'
    : removalPassword
      ? 'BlOckiT Website Blocker (Locked)'
      : 'BlOckiT Website Blocker';

  // DenyListURLs is the current key (iOS 14+); BlacklistedURLs is kept for older iOS.
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>AutoFilterEnabled</key>
            <false/>
            <key>ContentFilterUUID</key>
            <string>${contentFilterUuid}</string>
            <key>DenyListURLs</key>
            <array>
${urlItems}
            </array>
            <key>BlacklistedURLs</key>
            <array>
${urlItems}
            </array>
            <key>FilterType</key>
            <string>BuiltIn</string>
            <key>PayloadDescription</key>
            <string>Configures Web Content Filtering</string>
            <key>PayloadDisplayName</key>
            <string>Web Content Filter</string>
            <key>PayloadIdentifier</key>
            <string>${profileId}.contentfilter</string>
            <key>PayloadType</key>
            <string>com.apple.webcontent-filter</string>
            <key>PayloadUUID</key>
            <string>${filterUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>${lockPayload}
    </array>
    <key>PayloadDisplayName</key>
    <string>${displayName}</string>
    <key>PayloadIdentifier</key>
    <string>${profileId}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profileUuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
`;
}

class ValidationError extends Error {}

module.exports = {
  parseDomains,
  normaliseDomain,
  validateRemovalPassword,
  generatePermanentPassword,
  buildProfile,
  escapeXml,
  ValidationError,
  MAX_DOMAINS,
  PROFILE_ID,
};
