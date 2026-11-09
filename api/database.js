const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const filename = process.env.SQLITE_PATH || path.join(__dirname, "..", "data", "soc-helper.sqlite");
if (filename !== ":memory:") fs.mkdirSync(path.dirname(path.resolve(filename)), { recursive: true });

const database = new DatabaseSync(filename);
database.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS suspicious_ips (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    detections INTEGER NOT NULL DEFAULT 1,
    confidence INTEGER,
    sources TEXT NOT NULL DEFAULT '[]'
  );
`);

const saveSuspiciousIp = database.prepare(`
  INSERT INTO suspicious_ips (ip, first_seen, last_seen, detections, confidence, sources)
  VALUES (?, ?, ?, 1, ?, ?)
  ON CONFLICT(ip) DO UPDATE SET
    last_seen = excluded.last_seen,
    detections = suspicious_ips.detections + 1,
    confidence = excluded.confidence,
    sources = excluded.sources
`);

const listSuspiciousIps = database.prepare(`
  SELECT ip, first_seen AS firstSeen, last_seen AS lastSeen,
    detections, confidence, sources
  FROM suspicious_ips
  ORDER BY last_seen DESC
  LIMIT 500
`);

function save(ip, confidence, sources) {
  const now = new Date().toISOString();
  saveSuspiciousIp.run(ip, now, now, confidence ?? null, JSON.stringify(sources));
}

function list() {
  return listSuspiciousIps.all().map(row => ({ ...row, sources: JSON.parse(row.sources) }));
}

module.exports = { save, list };
