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

function buildProfile(domains) {
  const filterUuid = crypto.randomUUID().toUpperCase();
  const profileUuid = crypto.randomUUID().toUpperCase();
  const urlItems = domainsToUrls(domains)
    .map((u) => `                <string>${escapeXml(u)}</string>`)
    .join('\n');

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
            <string>com.example.blocker.contentfilter.${filterUuid}</string>
            <key>PayloadType</key>
            <string>com.apple.webcontent-filter</string>
            <key>PayloadUUID</key>
            <string>${filterUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Custom Focus Website Blocker</string>
    <key>PayloadIdentifier</key>
    <string>com.example.blocker.${profileUuid}</string>
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

module.exports = { parseDomains, normaliseDomain, buildProfile, escapeXml, ValidationError, MAX_DOMAINS };
