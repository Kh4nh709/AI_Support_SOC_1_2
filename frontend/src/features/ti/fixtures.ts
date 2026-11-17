// What the tests of the Threat Intel page serve: every key of the served objects, as the API sends them (the contract test holds the
// keys to the backend). Every value is made up: the documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32), example.* names, invented malware names and hashes. No real IOC.
import type {
  TiDay,
  TiIoc,
  TiListResponse,
  TiLog,
  TiMalwareCount,
  TiStats,
  TiStatus,
} from "../../api/ti";

/** A ThreatFox `ip:port` IOC with a confidence, a reference on abuse.ch and a few tags. */
function ioc(over: Partial<TiIoc> = {}): TiIoc {
  return {
    id: 1001,
    source: "threatfox",
    type: "ip:port",
    value: "203.0.113.7:443",
    malware: "Example.Rat",
    threat: "botnet_cc",
    confidence: 90,
    tags: ["rat", "c2"],
    reference: "https://threatfox.abuse.ch/ioc/1000001/",
    first_seen: "2026-11-17T02:15:30.123456+00:00",
    last_seen: "2026-11-17T00:10:05.000000+00:00",
    imported_at: "2026-11-17T00:10:05.000000+00:00",
    expires_at: "2026-12-17T00:10:05.000000+00:00",
    expired: false,
    hit_count: 0,
    last_hit: null,
    ...over,
  };
}

/** A MalwareBazaar hash: its confidence is null, as on every real row of that source. */
function hash(over: Partial<TiIoc> = {}): TiIoc {
  return ioc({
    id: 1002,
    source: "malwarebazaar",
    type: "sha256_hash",
    value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    malware: "Example.Loader",
    threat: null,
    confidence: null,
    tags: [],
    reference:
      "https://bazaar.abuse.ch/sample/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/",
    ...over,
  });
}

function url(over: Partial<TiIoc> = {}): TiIoc {
  return ioc({
    id: 1003,
    source: "urlhaus",
    type: "url",
    value: "http://payload.example.com/bin/a.exe",
    malware: "Example.Dropper",
    threat: "malware_download",
    confidence: 75,
    tags: ["exe"],
    reference: "https://urlhaus.abuse.ch/url/2000001/",
    ...over,
  });
}

function domain(over: Partial<TiIoc> = {}): TiIoc {
  return ioc({
    id: 1004,
    type: "domain",
    value: "c2.example.net",
    malware: "Example.Rat",
    confidence: 100,
    tags: [],
    reference: "https://threatfox.abuse.ch/ioc/1000002/",
    ...over,
  });
}

function list(rows: TiIoc[], over: Partial<TiListResponse> = {}): TiListResponse {
  return { rows, total: rows.length, page: 1, page_size: 50, ...over };
}

/** The 30 days to 2026-11-17, oldest first: dense, as the API serves them. The counts come from the index of the day. */
function days(count = 30, last = "2026-11-17"): TiDay[] {
  const end = Date.parse(`${last}T00:00:00Z`);
  const series: TiDay[] = [];
  for (let i = 0; i < count; i += 1) {
    const day = new Date(end - (count - 1 - i) * 86_400_000).toISOString().slice(0, 10);
    const threatfox = (i * 3) % 7;
    const urlhaus = i % 5 === 0 ? 2 : 0;
    const malwarebazaar = (i * 5) % 4;
    series.push({
      day,
      threatfox,
      urlhaus,
      malwarebazaar,
      total: threatfox + urlhaus + malwarebazaar,
    });
  }
  return series;
}

function stats(over: Partial<TiStats> = {}): TiStats {
  const top_malware: TiMalwareCount[] = [
    { malware: "Example.Rat", count: 42 },
    { malware: "Example.Loader", count: 31 },
    { malware: "Example.Dropper", count: 18 },
    { malware: "Example.Stealer", count: 9 },
    { malware: "Example.Miner", count: 7 },
  ];
  return {
    days: 30,
    today: "2026-11-17",
    sources: ["threatfox", "urlhaus", "malwarebazaar"],
    by_day: days(),
    top_malware,
    high_confidence: 57,
    matched_in_logs: 0,
    imported_today: 200,
    newest_malware: ["Example.Newest", "Example.Rat", "Example.Loader"],
    ...over,
  };
}

function log(over: Partial<TiLog> = {}): TiLog {
  return {
    id: 7,
    file: "ioc_2026-11-17.csv",
    started_at: "2026-11-17T00:10:04.500000+00:00",
    finished_at: "2026-11-17T00:10:05.250000+00:00",
    rows_total: 200,
    rows_new: 37,
    rows_updated: 163,
    rows_error: 0,
    status: "ok",
    message: null,
    ...over,
  };
}

function status(over: Partial<TiStatus> = {}): TiStatus {
  const latest = log();
  return { latest, latest_success: latest, stale: false, stale_after_hours: 26, ...over };
}

export const tiFixture = { ioc, hash, url, domain, list, days, stats, log, status };
