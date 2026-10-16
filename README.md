# BlOckiT

A website to block the list of url's on an iOS device.

Paste a list of domains, tap one button, and get a **signed** `.mobileconfig`
profile that blocks those sites in Safari (and other WebKit views) on your iPhone.

## ⚠️ Read this first: supervision

Apple only installs the `com.apple.webcontent-filter` payload (`FilterType: BuiltIn`)
on **supervised** iPhones. On a normal personal iPhone, installing the profile will fail.

To supervise your own phone, use **Apple Configurator** on a Mac
(*Prepare → Manual → Supervise*). **This erases the device**, so back it up first.

If you don't want to supervise, you can get the same result without this app:
*Settings → Screen Time → Content & Privacy Restrictions → App Store, Media, Web & Games
→ Web Content → Limit Adult Websites → Never Allow → Add Website.*

## How it works

```
public/index.html ──POST /api/generate──▶ lib/handler.js
                                            ├─ lib/profile.js  validate + normalise domains, build plist XML
                                            └─ lib/sign.js     node-forge PKCS#7 SignedData (SHA-256) → DER
                                          ◀── application/x-apple-aspen-config
```

- The form uses a native POST (not `fetch`), so iOS Safari passes the response
  straight to the profile installer.
- Every domain is blocked at both `https://domain` and `https://www.domain`.
- The profile includes `DenyListURLs` (iOS 14+) and the legacy `BlacklistedURLs`.
- Signing runs fully in memory with `node-forge`. It never shells out to `openssl`.
- The server never logs or stores domain lists.

| Path | Purpose |
| --- | --- |
| `public/` | Static frontend (`index.html`, `style.css`, `app.js`) |
| `api/generate.js` | Vercel function |
| `netlify/functions/generate.js` | Netlify function (rewritten from `/api/generate`) |
| `lib/` | Shared validation, plist builder, and signer |
| `dev-server.js` | Zero-dependency local server |
| `test/` | `node:test` suite (makes its own throwaway cert chain) |

## Environment variables

| Name | Required | Value |
| --- | --- | --- |
| `SSL_CERTIFICATE` | yes | Leaf certificate PEM (**RSA**) |
| `SSL_PRIVATE_KEY` | yes | Matching **unencrypted RSA** private key PEM (PKCS#1 or PKCS#8) |
| `SSL_INTERMEDIATE` | recommended | Intermediate CA PEM(s), concatenated |
| `ACCESS_CODE` | optional | If set, the server only signs profiles for requests that send this code |

You can paste PEMs multi-line, or as one line with literal `\n`. Keep the private key
in 1Password and paste it into the hosting dashboard. Never commit it (`.gitignore`
already excludes `.env`, `*.pem`, and `*.key`).

**Certificates:** `node-forge` can't sign with ECDSA keys, and certbot/Let's Encrypt now
issue ECDSA by default. Request an RSA key instead:

```bash
certbot certonly --key-type rsa --rsa-key-size 2048 -d yourdomain.com
```

Then `SSL_CERTIFICATE` = `cert.pem`, `SSL_INTERMEDIATE` = `chain.pem`, and
`SSL_PRIVATE_KEY` = `privkey.pem`. If the chain is publicly trusted, iOS shows the
profile as **Verified**. A self-signed certificate still installs, but iOS marks it
"Not Verified".

Without an `ACCESS_CODE`, anyone who finds your URL can get profiles signed with your
certificate. Set one if the site is public.

## Run locally

```bash
npm install
npm run dev:cert       # writes .env with a self-signed RSA cert (profiles show "Not Verified")
npm run dev            # http://localhost:3000
npm test
```

To use your real certificate locally instead, create `.env` with the variables from the table above.

## Deploy to Vercel

1. Push this repo to GitHub.
2. Go to vercel.com → **Add New Project** → import the repo. Use the **Other** framework
   preset and leave build/output settings alone (`vercel.json` sets `outputDirectory: public`).
3. **Settings → Environment Variables**: add the variables above.
4. Deploy. The page is served at `/` and the function at `/api/generate`.

Or deploy from the CLI: `npx vercel`, then `npx vercel env add SSL_CERTIFICATE`
(repeat for each variable), then `npx vercel --prod`.

## Deploy to Netlify

1. Push this repo to GitHub.
2. Go to app.netlify.com → **Add new site → Import an existing project** → pick the repo.
   `netlify.toml` already sets `publish = "public"`, the functions folder, and the
   `/api/generate` rewrite. Leave the build command empty.
3. **Site configuration → Environment variables**: add the variables above
   (scope: Functions).
4. Deploy.

## Install on the iPhone

1. Open your deployed URL in **Safari**, add sites, then tap **Block N sites** → **Allow**.
2. **Settings → Profile Downloaded → Install**.
3. To remove it: **Settings → General → VPN & Device Management** → the profile → **Remove**.
