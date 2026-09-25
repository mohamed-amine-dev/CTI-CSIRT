// -----------------------------------------------------------------------------
// API service layer.
//
// Thin typed wrappers around the FastAPI backend. Every function returns an
// axios promise; use the `useApi` / `useAsync` hooks (src/hooks) or call them
// directly from components. `errorText()` normalises the many failure shapes
// axios produces (network, HTTP status, validation) into a single string.
// -----------------------------------------------------------------------------

import axios from 'axios';

import { API_BASE, API_TOKEN } from '../config';

export const http = axios.create({
  baseURL: API_BASE,
  timeout: 30_000, // Shodan InternetDB / AI extraction can be slow
});

// --- auth helper for state-changing endpoints ------------------------------
function withAuth(config = {}) {
  if (!API_TOKEN) return config;
  return { ...config, headers: { ...(config.headers || {}), Authorization: `Bearer ${API_TOKEN}` } };
}

// --- meta ------------------------------------------------------------------
export const api = {
  health: () => http.get('/health'),

  // --- Alert Sheets (vulnerability_alerts) ------------------------------
  getAlerts: (params) => http.get('/api/v1/alerts', { params }),
  getAlert: (cve) => http.get(`/api/v1/alerts/${encodeURIComponent(cve)}`),
  getAlertStats: () => http.get('/api/v1/alerts/stats'),

  // --- Live threat feeds (raw_threat_intel) --------------------------------
  getFeeds: (params) => http.get('/api/v1/feeds', { params }),
  // --- Dark Web monitoring (enriched stream) --------------------------------
  getDarkWebMonitor: (channel, limit = 500) =>
    http.get('/api/v1/darkweb/monitor', { params: { channel, limit } }),

  // --- Org Exposure Search & Watchlist ------------------------------------
  searchExposure: (type, value, limit = 500) =>
    http.get('/api/v1/watchlist/search', { params: { type, value, limit } }),
  getWatchlist: () => http.get('/api/v1/watchlist'),
  addWatchlistTarget: (type, value, label = '') =>
    http.post('/api/v1/watchlist', { type, value, label }, withAuth()),
  deleteWatchlistTarget: (id) =>
    http.delete(`/api/v1/watchlist/${encodeURIComponent(id)}`, withAuth()),
  getWatchlistMatches: (limit = 50) =>
    http.get('/api/v1/watchlist/matches', { params: { limit } }),
  sweepWatchlist: () => http.post('/api/v1/watchlist/sweep', null, withAuth()),
  getFeedSources: () => http.get('/api/v1/feeds/sources'),
  getFeedCategories: () => http.get('/api/v1/feeds/categories'),
  getFeedTimeline: (days = 14) => http.get('/api/v1/feeds/timeline', { params: { days } }),

  // --- Threat Landscape (Threat & Malware Category Landscape) ---------------
  getThreatLandscape: (days = 60) => http.get('/api/v1/threats/landscape', { params: { days } }),
  getTopPorts: (days = 60) => http.get('/api/v1/threats/ports', { params: { days } }),
  getTopCves: (days = 60) => http.get('/api/v1/threats/cves', { params: { days } }),
  getTacticHeatmap: (days = 60) => http.get('/api/v1/threats/heatmap', { params: { days } }),

  // --- Threat origin (ip_geo_cache choropleth) -----------------------------
  getGeoSummary: (days = 60) => http.get('/api/v1/geo/summary', { params: { days } }),
  getGeoStatus: () => http.get('/api/v1/geo/status'),

  // --- Indicators (processed_iocs) -----------------------------------------
  getIocs: (params) => http.get('/api/v1/iocs', { params }),
  getIoc: (indicator) => http.get(`/api/v1/iocs/${encodeURIComponent(indicator)}`),
  getIocStats: () => http.get('/api/v1/iocs/stats'),
  getRecentIocs: (limit = 10) => http.get('/api/v1/iocs/recent', { params: { limit } }),

  // --- Shodan InternetDB enrichment (backend proxy, no CORS) ---------------
  getEnrich: (indicator) => http.get(`/api/v1/enrich/${encodeURIComponent(indicator)}`),

  // --- AI sheet pipeline status (pending/processing/done/failed) -----------
  getAiStatus: () => http.get('/api/v1/ai/status'),
  retryAiFailed: () => http.post('/api/v1/ai/retry-failed', null, withAuth()),

  // --- Real-time alerts (Phase 5) ------------------------------------------
  getNotifications: (params) => http.get('/api/v1/notifications', { params }),
  getUnreadCount: () => http.get('/api/v1/notifications/unread-count'),
  markNotificationRead: (id) => http.post(`/api/v1/notifications/${id}/read`, null, withAuth()),
  markAllNotificationsRead: () => http.post('/api/v1/notifications/read-all', null, withAuth()),
  testAlert: () => http.post('/api/v1/notifications/test', null, withAuth()),

  // --- Global search + export hub (Phase 6) --------------------------------
  searchAll: (q, kind, limit = 20) =>
    http.get('/api/v1/search', { params: { q, kind, limit } }),
  exportResource: (params) => http.get('/api/v1/export', { params, responseType: 'blob' }),

  // --- Read-only Data Explorer (/explore) ---------------------------------
  // All queries run through the SELECT-only `cti_ro` ClickHouse account.
  getExploreTables: () => http.get('/api/v1/explore/tables'),
  getExploreColumns: (table) => http.get(`/api/v1/explore/${encodeURIComponent(table)}/columns`),
  getExploreRows: (table, params) => http.get(`/api/v1/explore/${encodeURIComponent(table)}/rows`, { params }),
  runExploreQuery: (sql) => http.post('/api/v1/explore/query', { sql }),

  // --- Autonomous triage agent (/agent) -----------------------------------
  // Runs the LangGraph triage agent. Can take minutes while the local LLM is
  // throttled, so the client waits without its usual 30 s timeout.
  agentTriage: (payload) => http.post('/api/v1/agent/triage', payload, { ...withAuth(), timeout: 0 }),
  getAgentHistory: (limit = 25, q = '', verdict = 'all') =>
    http.get('/api/v1/agent/history', { params: { limit, q, verdict }, ...withAuth() }),

  // --- Threat Actors (ATT&CK module) --------------------------------------
  getActors: (search = '', filters = {}) =>
    http.get('/api/v1/actors', { params: { search, ...filters } }),
  getActor: (stixId) => http.get(`/api/v1/actors/${encodeURIComponent(stixId)}`),
  getActorAttackMatrix: (stixId) => http.get(`/api/v1/actors/${encodeURIComponent(stixId)}/attack-matrix`),
  getActorFilters: () => http.get('/api/v1/actors/filters'),
  getActorStats: () => http.get('/api/v1/actors/stats'),
  getActorRules: (stixId) => http.get(`/api/v1/actors/${encodeURIComponent(stixId)}/rules`),
  syncActors: () => http.post('/api/v1/actors/sync', null, { ...withAuth(), timeout: 60_000 }),
  askActors: (query) => http.post('/api/v1/actors/ask', { query }, { ...withAuth(), timeout: 120_000 }),
  attributeIoc: (stixId, indicator, iocType) =>
    http.post(
      `/api/v1/actors/${encodeURIComponent(stixId)}/attribute-ioc`,
      { indicator, type: iocType },
      withAuth(),
    ),
  unattributeIoc: (stixId, indicator, iocType) =>
    http.delete(`/api/v1/actors/${encodeURIComponent(stixId)}/attribute-ioc`, {
      params: { indicator, type: iocType },
      ...withAuth(),
    }),

  // --- Malware & tools (ATT&CK module) -------------------------------------
  getMalware: (stixId) => http.get(`/api/v1/malware/${encodeURIComponent(stixId)}`),
  getMalwareList: (params) => http.get('/api/v1/malware', { params }),
  getMalwareFilters: () => http.get('/api/v1/malware/filters'),

  // --- Sample scanner (Malware & Tools -> sample scanner) ------------------
  getSamplesStatus: () => http.get('/api/v1/samples/status'),
  scanSample: (file, onProgress) =>
    http.post('/api/v1/samples/scan', file, {
      ...withAuth({ headers: { 'Content-Type': 'multipart/form-data' } }),
      timeout: 60_000,
      onUploadProgress: (e) => onProgress && onProgress(e.total ? Math.round((e.loaded / e.total) * 100) : 0),
    }),
  generateSampleRules: (quarantineId, iocs = []) =>
    http.post('/api/v1/samples/rules', { quarantine_id: quarantineId, iocs }, withAuth()),
  validateSampleRules: (engine, content) =>
    http.post('/api/v1/samples/validate', { engine, content }, withAuth()),

  // --- Network Analysis (PCAP investigation module) -----------------------
  getPcapStatus: () => http.get('/api/v1/pcap/status'),
  analyzePcap: (file, onProgress) =>
    http.post('/api/v1/pcap/analyze', file, {
      ...withAuth({ headers: { 'Content-Type': 'multipart/form-data' } }),
      timeout: 300_000,
      onUploadProgress: (e) => onProgress && onProgress(e.total ? Math.round((e.loaded / e.total) * 100) : 0),
    }),
  listPcaps: () => http.get('/api/v1/pcap/list'),
  getPcap: (captureId) => http.get(`/api/v1/pcap/${encodeURIComponent(captureId)}`),
  getPcapGraph: (captureId) => http.get(`/api/v1/pcap/${encodeURIComponent(captureId)}/graph`),
  getPcapSummary: (captureId) =>
    http.get(`/api/v1/pcap/${encodeURIComponent(captureId)}/summary`, { timeout: 180_000 }),
  generatePcapRules: (captureId, iocs = []) =>
    http.post(`/api/v1/pcap/${encodeURIComponent(captureId)}/rules`, { iocs }, withAuth()),

  // --- state-changing operations (Bearer token required) -------------------
  // On-demand Alert Sheet generation is ASYNC: POST returns a job_id (202),
  // poll getProcessJob until it reaches "done" or "failed".
  processText: (text, cve) => http.post('/api/v1/process', cve ? { text, cve } : { text }, withAuth()),
  getProcessJob: (jobId) => http.get(`/api/v1/process/${encodeURIComponent(jobId)}`),
  triggerIngest: () => http.post('/api/v1/ingest', null, withAuth()),
  // Admin "Force Sync Feeds": launches every collector in the background (202),
  // then poll status until `running` becomes false.
  forceSync: () => http.post('/api/v1/ingest/force-sync', null, { ...withAuth(), timeout: 30_000 }),
  getIngestStatus: () => http.get('/api/v1/ingest/status', withAuth()),
};

// -----------------------------------------------------------------------------
// Error normalisation
// -----------------------------------------------------------------------------
export function errorText(error) {
  if (!error) return 'Unknown error';
  if (error.response) {
    const detail = error.response.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) return detail.map((d) => d.msg).join('; ');
    if (typeof detail === 'object' && detail) return JSON.stringify(detail);
    return `Request failed (${error.response.status})`;
  }
  if (error.code === 'ECONNABORTED') return 'Request timed out';
  if (error.request) return `No response from server (${error.message})`;
  return error.message || String(error);
}

/** Guard that unwraps axios responses so components never touch `.data.data`. */
export async function unwrap(promise) {
  const res = await promise;
  return res.data;
}

/** Trigger a browser download for an export blob (Phase 6). */
export function downloadBlob(response) {
  const disposition = response.headers?.['content-disposition'] || '';
  const match = disposition.match(/filename="?([^"]+)"?/);
  const name = match ? match[1] : `cti_export_${Date.now()}.dat`;
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
  return name;
}
