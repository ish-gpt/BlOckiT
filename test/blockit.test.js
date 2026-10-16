'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const forge = require('node-forge');

const {
  normaliseDomain,
  parseDomains,
  validateRemovalPassword,
  generatePermanentPassword,
  buildProfile,
  ValidationError,
  PROFILE_ID,
} = require('../lib/profile');

// ---------- throwaway CA -> intermediate -> leaf chain ----------

function keyPair() {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const key = forge.pki.privateKeyFromPem(pem);
  return { pem, key, pub: forge.pki.setRsaPublicKey(key.n, key.e) };
}

function makeCert(subjectCN, keys, issuer, isCA) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.pub;
  cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  cert.setSubject([{ name: 'commonName', value: subjectCN }]);
  cert.setIssuer(issuer ? issuer.cert.subject.attributes : [{ name: 'commonName', value: subjectCN }]);
  cert.setExtensions([
    { name: 'basicConstraints', cA: isCA },
    { name: 'keyUsage', digitalSignature: true, keyCertSign: isCA },
  ]);
  cert.sign(issuer ? issuer.keys.key : keys.key, forge.md.sha256.create());
  return { cert, keys, pem: forge.pki.certificateToPem(cert) };
}

const root = (() => { const k = keyPair(); return makeCert('Test Root', k, null, true); })();
const inter = (() => { const k = keyPair(); return makeCert('Test Intermediate', k, root, true); })();
const leaf = (() => { const k = keyPair(); return makeCert('blockit.test', k, inter, false); })();

function freshModules(env) {
  for (const k of ['SSL_CERTIFICATE', 'SSL_PRIVATE_KEY', 'SSL_INTERMEDIATE', 'ACCESS_CODE']) delete process.env[k];
  Object.assign(process.env, env);
  for (const id of Object.keys(require.cache)) if (id.includes('/lib/')) delete require.cache[id];
  return { sign: require('../lib/sign'), handler: require('../lib/handler') };
}

const goodEnv = {
  SSL_CERTIFICATE: leaf.pem,
  SSL_PRIVATE_KEY: leaf.keys.pem,
  SSL_INTERMEDIATE: inter.pem,
};

// ---------- domain parsing ----------

test('normaliseDomain strips scheme, path, port, wildcard and case', () => {
  assert.equal(normaliseDomain('https://www.YouTube.com/watch?v=1'), 'www.youtube.com');
  assert.equal(normaliseDomain('*.reddit.com'), 'reddit.com');
  assert.equal(normaliseDomain('x.com:443'), 'x.com');
  assert.equal(normaliseDomain('münchen.de'), 'xn--mnchen-3ya.de');
});

test('normaliseDomain rejects junk and injection attempts', () => {
  for (const bad of ['localhost', '1.2.3.4', '<script>.com', 'a..com', '-bad.com', 'foo"bar.com', '']) {
    assert.equal(normaliseDomain(bad), null, bad);
  }
});

test('parseDomains de-duplicates and validates', () => {
  assert.deepEqual(parseDomains('a.com\nA.com\n https://b.org/x \n\n'), ['a.com', 'b.org']);
  assert.throws(() => parseDomains(''), ValidationError);
  assert.throws(() => parseDomains('good.com\nnot a domain!'), ValidationError);
  assert.throws(() => parseDomains('x'.repeat(30000)), ValidationError);
});

test('buildProfile inserts URLs, fixed identifiers and fresh UUIDs', () => {
  const xml = buildProfile(['example.com', 'www.foo.com']);
  assert.match(xml, /<string>https:\/\/example\.com<\/string>/);
  assert.match(xml, /<string>https:\/\/www\.example\.com<\/string>/);
  assert.match(xml, /<string>https:\/\/foo\.com<\/string>/); // www. input also blocks apex
  assert.doesNotMatch(xml, /www\.www\./);
  const uuids = [...xml.matchAll(/<key>PayloadUUID<\/key>\s*<string>([0-9A-F-]{36})<\/string>/g)].map((m) => m[1]);
  assert.equal(uuids.length, 2);
  assert.notEqual(uuids[0], uuids[1]);
  assert.match(xml, /<key>PayloadIdentifier<\/key>\s*<string>com\.blockit\.profile<\/string>/);
  assert.match(xml, /<string>com\.blockit\.profile\.contentfilter<\/string>/);
  assert.equal(PROFILE_ID, 'com.blockit.profile');
  assert.doesNotMatch(xml, /profileRemovalPassword/);
  const cf = xml.match(/<key>ContentFilterUUID<\/key>\s*<string>([0-9A-F-]{36})<\/string>/);
  assert.ok(cf, 'ContentFilterUUID present');
  assert.ok(!uuids.includes(cf[1]), 'ContentFilterUUID is distinct');
});

test('two builds share identifiers so the new profile replaces the old one', () => {
  const ids = (xml) => [...xml.matchAll(/<key>PayloadIdentifier<\/key>\s*<string>([^<]+)<\/string>/g)].map((m) => m[1]);
  assert.deepEqual(ids(buildProfile(['a.com'])), ids(buildProfile(['b.com'])));
});

test('locked profile embeds an escaped removal password payload', () => {
  const xml = buildProfile(['a.com'], { removalPassword: 'p<&>"ss' });
  assert.match(xml, /<string>com\.apple\.profileRemovalPassword<\/string>/);
  assert.match(xml, /<key>RemovalPassword<\/key>\s*<string>p&lt;&amp;&gt;&quot;ss<\/string>/);
  assert.match(xml, /\(Locked\)/);
  const uuids = [...xml.matchAll(/<key>PayloadUUID<\/key>\s*<string>([0-9A-F-]{36})<\/string>/g)].map((m) => m[1]);
  assert.equal(new Set(uuids).size, 3);
});

test('validateRemovalPassword rules', () => {
  assert.equal(validateRemovalPassword(''), null);
  assert.equal(validateRemovalPassword(undefined), null);
  assert.equal(validateRemovalPassword('longenough', 'longenough'), 'longenough');
  assert.throws(() => validateRemovalPassword('short'), /at least 6/);
  assert.throws(() => validateRemovalPassword('x'.repeat(129)), /under 128/);
  assert.throws(() => validateRemovalPassword('bad\u0000pass'), /cannot accept/);
  assert.throws(() => validateRemovalPassword('longenough', 'different'), /don't match/);
  assert.throws(() => validateRemovalPassword(['array']), /not valid/);
});

test('permanent profiles get one-off identifiers that nothing else can replace', () => {
  const ids = (xml) => [...xml.matchAll(/<key>PayloadIdentifier<\/key>\s*<string>([^<]+)<\/string>/g)].map((m) => m[1]);
  const cfu = (xml) => xml.match(/<key>ContentFilterUUID<\/key>\s*<string>([^<]+)</)[1];
  const a = buildProfile(['a.com'], { removalPassword: 'x'.repeat(10), permanent: true });
  const b = buildProfile(['a.com'], { removalPassword: 'x'.repeat(10), permanent: true });
  const normal = buildProfile(['a.com']);
  assert.match(ids(a).at(-1), /^com\.blockit\.profile\.permanent\.[0-9A-F-]{36}$/);
  assert.notDeepEqual(ids(a), ids(b));
  assert.ok(!ids(a).some((id) => ids(normal).includes(id)));
  assert.notEqual(cfu(a), cfu(normal));
  assert.match(a, /\(Permanent\)/);
});

test('generatePermanentPassword is long, random and plist-safe', () => {
  const p1 = generatePermanentPassword();
  assert.match(p1, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(p1, generatePermanentPassword());
});

// ---------- signing ----------

test('signProfile produces DER PKCS#7 with attached content, chain and valid signature', () => {
  const { sign } = freshModules(goodEnv);
  const xml = buildProfile(['example.com']);
  const der = sign.signProfile(xml);

  assert.ok(Buffer.isBuffer(der));
  assert.equal(der[0], 0x30); // ASN.1 SEQUENCE

  const msg = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(der.toString('binary')));
  assert.equal(forge.util.decodeUtf8(msg.rawCapture.content.value[0].value), xml);
  assert.equal(msg.certificates.length, 2);

  // Verify the RSA signature over the authenticated attributes
  const attrs = msg.rawCapture.authenticatedAttributes;
  const set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs);
  const md = forge.md.sha256.create().update(forge.asn1.toDer(set).getBytes());
  assert.ok(leaf.cert.publicKey.verify(md.digest().getBytes(), msg.rawCapture.signature));
});

test('signing config errors are explicit', () => {
  assert.throws(() => freshModules({}).sign.signProfile('x'), /must be set/);
  const other = keyPair();
  assert.throws(
    () => freshModules({ ...goodEnv, SSL_PRIVATE_KEY: other.pem }).sign.signProfile('x'),
    /does not match/,
  );
  assert.throws(
    () => freshModules({ ...goodEnv, SSL_PRIVATE_KEY: '-----BEGIN EC PRIVATE KEY-----\nAA\n-----END EC PRIVATE KEY-----' }).sign.signProfile('x'),
    /EC key/,
  );
});

test('PEMs with escaped \\n in env vars are accepted', () => {
  const { sign } = freshModules({
    SSL_CERTIFICATE: leaf.pem.replace(/\r?\n/g, '\\n'),
    SSL_PRIVATE_KEY: leaf.keys.pem.replace(/\r?\n/g, '\\n'),
  });
  assert.ok(sign.signProfile('hi').length > 0);
});

// ---------- handler ----------

test('handler returns signed profile with exact headers', () => {
  const { handler } = freshModules(goodEnv);
  const res = handler.generate({
    method: 'POST',
    body: 'domains=instagram.com%0Atiktok.com',
    contentType: 'application/x-www-form-urlencoded',
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers['Content-Type'], 'application/x-apple-aspen-config');
  assert.equal(res.headers['Content-Disposition'], 'attachment; filename="blocklist.mobileconfig"');
  assert.ok(Buffer.isBuffer(res.body));
});

test('handler rejects GET, bad input and escapes error output', () => {
  const { handler } = freshModules(goodEnv);
  assert.equal(handler.generate({ method: 'GET' }).status, 405);
  const res = handler.generate({ method: 'POST', body: { domains: '<img src=x onerror=alert(1)>' } });
  assert.equal(res.status, 400);
  assert.doesNotMatch(res.body, /<img/);
  assert.match(res.body, /&lt;img/);
});

test('handler enforces ACCESS_CODE when set', () => {
  const { handler } = freshModules({ ...goodEnv, ACCESS_CODE: 's3cret' });
  assert.equal(handler.generate({ method: 'POST', body: { domains: 'a.com' } }).status, 401);
  assert.equal(handler.generate({ method: 'POST', body: { domains: 'a.com', accessCode: 'nope' } }).status, 401);
  assert.equal(handler.generate({ method: 'POST', body: { domains: 'a.com', accessCode: 's3cret' } }).status, 200);
});

test('handler hides signing misconfiguration details from the client', () => {
  const { handler } = freshModules({});
  const res = handler.generate({ method: 'POST', body: { domains: 'a.com' } });
  assert.equal(res.status, 500);
  assert.doesNotMatch(res.body, /SSL_/);
});

test('handler only locks when the Lock it switch is on', () => {
  const { handler } = freshModules(goodEnv);
  const contentOf = (res) => {
    const msg = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(res.body.toString('binary')));
    return forge.util.decodeUtf8(msg.rawCapture.content.value[0].value);
  };

  const locked = handler.generate({
    method: 'POST',
    body: { domains: 'a.com', lock: 'on', lockPassword: 'friend-secret', lockPasswordConfirm: 'friend-secret' },
  });
  assert.equal(locked.status, 200);
  assert.match(contentOf(locked), /friend-secret/);

  const ignored = handler.generate({ method: 'POST', body: { domains: 'a.com', lockPassword: 'friend-secret' } });
  assert.equal(ignored.status, 200);
  assert.doesNotMatch(contentOf(ignored), /friend-secret|profileRemovalPassword/);

  assert.equal(handler.generate({ method: 'POST', body: { domains: 'a.com', lock: 'on' } }).status, 400);
  const mismatch = handler.generate({
    method: 'POST',
    body: { domains: 'a.com', lock: 'on', lockPassword: 'friend-secret', lockPasswordConfirm: 'nope-nope' },
  });
  assert.equal(mismatch.status, 400);
  assert.doesNotMatch(mismatch.body, /friend-secret/);
});

test('handler permanent mode: needs the tick, never echoes or reuses a password', () => {
  const { handler } = freshModules(goodEnv);
  const contentOf = (res) => {
    const msg = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(res.body.toString('binary')));
    return forge.util.decodeUtf8(msg.rawCapture.content.value[0].value);
  };
  const pwOf = (xml) => xml.match(/<key>RemovalPassword<\/key>\s*<string>([^<]+)</)[1];

  assert.equal(handler.generate({ method: 'POST', body: { domains: 'a.com', lock: 'on', lockMode: 'permanent' } }).status, 400);

  const body = { domains: 'a.com', lock: 'on', lockMode: 'permanent', permanentAck: 'yes', lockPassword: 'mine-known' };
  const r1 = handler.generate({ method: 'POST', body });
  const r2 = handler.generate({ method: 'POST', body });
  assert.equal(r1.status, 200);
  const x1 = contentOf(r1);
  assert.doesNotMatch(x1, /mine-known/); // a typed password is ignored in permanent mode
  assert.match(pwOf(x1), /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(pwOf(x1), pwOf(contentOf(r2)));
  assert.deepEqual(Object.keys(r1.headers).sort(), ['Cache-Control', 'Content-Disposition', 'Content-Type']);
});

// export chain for the manual openssl check
test.after(() => {
  if (process.env.BLOCKIT_DUMP_DIR) {
    const fs = require('fs');
    const path = require('path');
    const d = process.env.BLOCKIT_DUMP_DIR;
    fs.writeFileSync(path.join(d, 'root.pem'), root.pem);
    fs.writeFileSync(path.join(d, 'inter.pem'), inter.pem);
    fs.writeFileSync(path.join(d, 'leaf.pem'), leaf.pem);
    fs.writeFileSync(path.join(d, 'leaf.key'), leaf.keys.pem);
  }
});
