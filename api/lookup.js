const net = require("node:net");
const database = require("./database");

const json = (res, status, body) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.end(JSON.stringify(body));
};

function normalize(input) {
  const raw = String(input ?? "").trim();
  if (!raw || raw.length > 2048) throw new Error("Enter an indicator up to 2048 characters.");
  const ipVersion = net.isIP(raw);
  if (ipVersion === 4) return { value: raw, type: "ip", recognizedAs: "IPv4 address" };
  if (ipVersion === 6) return { value: raw.toLowerCase(), type: "ip", recognizedAs: "IPv6 address" };

  const lower = raw.toLowerCase();
  const hashNames = { 32: "MD5 hash", 40: "SHA-1 hash", 64: "SHA-256 hash" };
  if (/^[a-f0-9]+$/.test(lower) && hashNames[lower.length]) {
    return { value: lower, type: "hash", recognizedAs: hashNames[lower.length] };
  }

  if (/^https?:\/\//i.test(raw)) {
    const parsed = new URL(raw);
    if (parsed.username || parsed.password) throw new Error("URLs with embedded credentials are not supported.");
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (!host) throw new Error("That URL has no hostname.");
    return { value: parsed.href, host, type: "url", recognizedAs: "URL (host: " + host + ")" };
  }

  const host = lower.replace(/\.$/, "");
  if (net.isIP(host) === 4) return { value: host, type: "ip", recognizedAs: "IPv4 address" };
  if (net.isIP(host) === 6) return { value: host, type: "ip", recognizedAs: "IPv6 address" };
  const validDomain = host.length <= 253 && host.includes(".") &&
    host.split(".").every(label => label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
  if (!validDomain) throw new Error("Unrecognized format. Enter an IP, domain, HTTP(S) URL, or MD5/SHA-1/SHA-256 hash.");
  return { value: host, host, type: "domain", recognizedAs: "Domain name" };
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(6000) });
  if (!response.ok) throw new Error("Provider returned HTTP " + response.status);
  return response.json();
}

const unavailable = (source, summary) => ({ source, status: "unavailable", malicious: null, summary });

async function abuseIpdb(indicator) {
  if (indicator.type !== "ip") return { source: "AbuseIPDB", status: "not_applicable", malicious: null };
  if (!process.env.ABUSEIPDB_API_KEY) return unavailable("AbuseIPDB", "Add ABUSEIPDB_API_KEY in Render Environment settings.");
  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", indicator.value);
    url.searchParams.set("maxAgeInDays", "90");
    const body = (await fetchJson(url, { headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: "application/json" } })).data || {};
    const score = Number(body.abuseConfidenceScore || 0);
    return {
      source: "AbuseIPDB", status: "ok", malicious: score >= 25, confidence: score,
      reports: Number(body.totalReports || 0),
      summary: score + "% abuse confidence · " + Number(body.totalReports || 0) + " reports"
    };
  } catch (error) { return unavailable("AbuseIPDB", error.message); }
}

async function urlhaus(indicator) {
  if (!["url", "domain"].includes(indicator.type)) return { source: "URLhaus", status: "not_applicable", malicious: null };
  if (!process.env.URLHAUS_AUTH_KEY) return unavailable("URLhaus", "Add URLHAUS_AUTH_KEY in Render Environment settings.");
  try {
    const endpoint = indicator.type === "url" ? "https://urlhaus-api.abuse.ch/v1/url/" : "https://urlhaus-api.abuse.ch/v1/host/";
    const form = new URLSearchParams(indicator.type === "url" ? { url: indicator.value } : { host: indicator.host || indicator.value });
    const body = await fetchJson(endpoint, {
      method: "POST",
      headers: { "Auth-Key": process.env.URLHAUS_AUTH_KEY, "Content-Type": "application/x-www-form-urlencoded" },
      body: form
    });
    const hit = body.query_status === "ok";
    const matches = Number(body.url_count || (body.url ? 1 : 0));
    return {
      source: "URLhaus", status: "ok", malicious: hit, matches,
      summary: hit ? "Listed in URLhaus (" + matches + " matching URLs)" : "No matching malware URL found"
    };
  } catch (error) { return unavailable("URLhaus", error.message); }
}

async function otx(indicator) {
  if (!process.env.OTX_API_KEY) return unavailable("OTX", "Add OTX_API_KEY in Render Environment settings.");
  try {
    const type = {
      ip: net.isIP(indicator.value) === 6 ? "IPv6" : "IPv4",
      domain: "domain", url: "url", hash: "file"
    }[indicator.type];
    const body = await fetchJson(
      "https://otx.alienvault.com/api/v1/indicators/" + type + "/" + encodeURIComponent(indicator.value) + "/general",
      { headers: { "X-OTX-API-KEY": process.env.OTX_API_KEY, Accept: "application/json" } }
    );
    const pulses = Number(body.pulse_info?.count || 0);
    return {
      source: "OTX", status: "ok", malicious: pulses > 0, pulses,
      summary: pulses ? "Found in " + pulses + " threat pulses" : "No threat pulses found"
    };
  } catch (error) { return unavailable("OTX", error.message); }
}

function splitIndicators(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.flatMap(item => String(item ?? "").split(/[\s,;]+/)).map(item => item.trim()).filter(Boolean);
}

async function analyze(input) {
  let indicator;
  try { indicator = normalize(input); }
  catch (error) {
    return {
      input: String(input ?? ""),
      indicator: { value: String(input ?? ""), type: "unknown", recognizedAs: "Unrecognized format" },
      verdict: "invalid", confidence: null, summary: error.message, sources: []
    };
  }
  const sources = await Promise.all([abuseIpdb(indicator), urlhaus(indicator), otx(indicator)]);
  const available = sources.filter(source => source.status === "ok");
  const flagged = available.filter(source => source.malicious);
  const verdict = !available.length ? "unknown" : flagged.length ? "malicious" : "clean";
  if (indicator.type === "ip" && verdict === "malicious") {
    database.save(indicator.value, Math.round(flagged.length / available.length * 100), flagged.map(source => source.source));
  }
  return {
    indicator,
    verdict,
    confidence: available.length ? Math.round(flagged.length / available.length * 100) : null,
    summary: flagged.length
      ? "Flagged by " + flagged.length + " of " + available.length + " available sources."
      : available.length ? "No available source flagged this indicator."
      : "No configured source returned a verdict.",
    sources
  };
}

module.exports = async (req, res) => {
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  if (!["GET", "POST"].includes(req.method)) return json(res, 405, { error: "Use GET or POST." });
  try {
    let body = req.method === "GET" ? req.query || {} : req.body || {};
    if (typeof body === "string") body = JSON.parse(body);
    const input = Array.isArray(body) ? body : body.indicators ?? body.indicator ?? body.q;
    const indicators = splitIndicators(input);
    if (!indicators.length) return json(res, 400, { error: "Provide one or more indicators." });
    if (indicators.length > 20) return json(res, 400, { error: "Send no more than 20 indicators per request." });

    const results = await Promise.all(indicators.map(analyze));
    if (results.length === 1) return json(res, 200, { ...results[0], checkedAt: new Date().toISOString() });
    const counts = {
      total: results.length,
      malicious: results.filter(result => result.verdict === "malicious").length,
      clean: results.filter(result => result.verdict === "clean").length,
      unknown: results.filter(result => result.verdict === "unknown").length,
      invalid: results.filter(result => result.verdict === "invalid").length
    };
    return json(res, 200, { results, counts, checkedAt: new Date().toISOString() });
  } catch (error) {
    return json(res, 400, { error: error.message || "Invalid request." });
  }
};

module.exports.listSuspiciousIps = database.list;
