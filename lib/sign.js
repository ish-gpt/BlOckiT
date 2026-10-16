'use strict';

const forge = require('node-forge');

const CERT_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

class ConfigError extends Error {}

let cached = null;

/** Env vars often hold PEMs with literal "\n" sequences instead of real newlines. */
function readPemEnv(name) {
  const value = process.env[name];
  return value ? value.replace(/\\n/g, '\n').trim() : '';
}

function loadSigningMaterial() {
  if (cached) return cached;

  const certPem = readPemEnv('SSL_CERTIFICATE');
  const keyPem = readPemEnv('SSL_PRIVATE_KEY');
  const chainPem = readPemEnv('SSL_INTERMEDIATE');

  if (!certPem || !keyPem) {
    throw new ConfigError('SSL_CERTIFICATE and SSL_PRIVATE_KEY must be set.');
  }
  if (/BEGIN EC PRIVATE KEY/.test(keyPem)) {
    throw new ConfigError('SSL_PRIVATE_KEY is an EC key; node-forge can only sign with RSA keys.');
  }

  let certificate, key;
  try {
    certificate = forge.pki.certificateFromPem(certPem);
  } catch (e) {
    throw new ConfigError('SSL_CERTIFICATE is not a valid RSA certificate PEM.');
  }
  try {
    key = forge.pki.privateKeyFromPem(keyPem);
  } catch (e) {
    throw new ConfigError('SSL_PRIVATE_KEY is not a valid unencrypted RSA private key PEM.');
  }
  if (!certificate.publicKey.n || certificate.publicKey.n.compareTo(key.n) !== 0) {
    throw new ConfigError('SSL_PRIVATE_KEY does not match SSL_CERTIFICATE.');
  }

  const intermediates = (chainPem.match(CERT_BLOCK_RE) || []).map((pem) => forge.pki.certificateFromPem(pem));

  cached = { certificate, key, intermediates };
  return cached;
}

/** Returns the profile wrapped in a DER-encoded PKCS#7 SignedData (content attached). */
function signProfile(xml) {
  const { certificate, key, intermediates } = loadSigningMaterial();

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(xml, 'utf8');
  p7.addCertificate(certificate);
  intermediates.forEach((c) => p7.addCertificate(c));
  p7.addSigner({
    key,
    certificate,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign();

  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, 'binary');
}

module.exports = { signProfile, loadSigningMaterial, ConfigError };
