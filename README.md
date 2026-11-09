# SOC Helper

A Node.js web service with a browser lookup page and a JSON threat-intelligence API. It accepts IPv4/IPv6 addresses, domains, HTTP(S) URLs, and MD5/SHA-1/SHA-256 hashes. Paste up to 20 indicators, separated by lines, spaces, commas, or semicolons, to look them up together.

## Run locally

    npm install
    npm start

The service reads PORT (default 10000).

## API

- GET /api/lookup?indicator=1.2.3.4
- POST /api/lookup with JSON body {"indicators":["1.2.3.4","example.com"]}
- POST /api/lookup with JSON body {"indicator":"1.2.3.4 example.com"}

Each result includes the format recognition (such as IPv4 address, domain name, or SHA-256 hash), normalized indicator, normalized verdict, provider evidence, and timestamp. A single result is returned for one input. Multiple inputs return a results array and verdict counts. The q parameter is also accepted.

## Provider credentials

Add these as Render service environment variables. Never commit keys to source control:

- ABUSEIPDB_API_KEY
- URLHAUS_AUTH_KEY
- OTX_API_KEY

Provider keys are optional, but only configured sources can return evidence.

## Render

- Runtime: Node
- Build command: npm install
- Start command: npm start
- Health endpoint: /healthz

The endpoint currently has no caller authentication or request rate limiting; add both before exposing it broadly with provider credentials.

