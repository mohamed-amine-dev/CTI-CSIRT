// -----------------------------------------------------------------------------
// Indicator (IoC) extraction + typing helpers.
// The backend stores indicators in ClickHouse; the feeds view additionally
// extracts IPs/domains/hashes straight from the raw feed text with the regexes
// below so analysts can copy them with one click.
// -----------------------------------------------------------------------------

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const BTC_RE = /\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b/g;

function isPrivateIp(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
}

/** Extract typed indicators from a raw text blob. */
export function extractIoCs(text = '') {
  const found = [];
  const push = (value, type) => {
    const v = value.trim();
    if (!v || found.some((f) => f.type === type && f.value.toLowerCase() === v.toLowerCase())) return;
    found.push({ value: v, type });
  };

  // Hashes first (a 32-hex string is also "something else"; don't double count).
  for (const m of text.match(SHA256_RE) || []) push(m, 'sha256');
  for (const m of text.match(SHA1_RE) || []) push(m, 'sha1');
  for (const m of text.match(MD5_RE) || []) push(m, 'md5');

  for (const m of text.match(BTC_RE) || []) push(m, 'btc');

  for (const m of text.match(IPV4_RE) || []) {
    if (!isPrivateIp(m)) push(m, 'ipv4');
  }

  for (const m of text.match(URL_RE) || []) push(m, 'url');

  for (const m of text.match(DOMAIN_RE) || []) {
    if (!m.toLowerCase().endsWith('.onion')) push(m, 'domain');
  }

  for (const m of text.match(CVE_RE) || []) push(m.toUpperCase(), 'cve');

  return found.slice(0, 12); // cap per card to keep the UI tidy
}

/** Guess whether a search term looks like an IP, domain, hash or CVE. */
export function guessIocType(term) {
  const t = term.trim().toLowerCase();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) return 'ipv4';
  if (/^[a-f0-9]{64}$/i.test(t)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(t)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(t)) return 'md5';
  if (/^cve-\d{4}-\d{4,7}$/i.test(t)) return 'cve';
  if (/^https?:\/\/\S+$/i.test(t)) return 'url';
  if (/\.(onion)$/i.test(t)) return 'onion';
  if (t.includes('.')) return 'domain';
  return 'unknown';
}

export const IOC_TYPE_LABELS = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  cidr: 'CIDR',
  domain: 'Domain',
  url: 'URL',
  sha256: 'SHA-256',
  sha1: 'SHA-1',
  md5: 'MD5',
  cve: 'CVE',
  ja3: 'JA3',
  email: 'E-mail',
  onion: 'Onion',
  btc: 'BTC',
  unknown: 'Unknown',
};
