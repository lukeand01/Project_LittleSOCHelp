# Signal

Signal is a Node.js web service with a browser lookup page and JSON threat-intelligence API for IPv4/IPv6, domains, URLs, and MD5/SHA-1/SHA-256 hashes.

## Run locally

    npm install
    npm start

The service reads PORT (default 10000).

## API

- GET /api/lookup?indicator=example.com
- POST /api/lookup with JSON body {"indicator":"example.com"}

The response returns malicious, clean, or unknown, source evidence, consensus confidence, and check time. The q parameter is also accepted.

## Provider keys

Add these as Render service environment variables. Do not commit keys to source control:

- ABUSEIPDB_API_KEY
- URLHAUS_AUTH_KEY
- OTX_API_KEY

Provider keys are optional, but only configured sources can return evidence.

## Render

- Runtime: Node
- Build command: npm install
- Start command: npm start
- Health check: /healthz

The endpoint currently has no caller authentication or request rate limiting; add both before exposing it broadly with provider credentials.
