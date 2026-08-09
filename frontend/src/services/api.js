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

  // --- Fiches d'Alerte (vulnerability_alerts) ------------------------------
  getAlerts: (params) => http.get('/api/v1/alerts', { params }),
  getAlert: (cve) => http.get(`/api/v1/alerts/${encodeURIComponent(cve)}`),
  getAlertStats: () => http.get('/api/v1/alerts/stats'),

  // --- Live threat feeds (raw_threat_intel) --------------------------------
  getFeeds: (params) => http.get('/api/v1/feeds', { params }),
  getFeedSources: () => http.get('/api/v1/feeds/sources'),
  getFeedCategories: () => http.get('/api/v1/feeds/categories'),
  getFeedTimeline: (days = 14) => http.get('/api/v1/feeds/timeline', { params: { days } }),

  // --- Indicators (processed_iocs) -----------------------------------------
  getIocs: (params) => http.get('/api/v1/iocs', { params }),
  getIoc: (indicator) => http.get(`/api/v1/iocs/${encodeURIComponent(indicator)}`),
  getIocStats: () => http.get('/api/v1/iocs/stats'),

  // --- Shodan InternetDB enrichment (backend proxy, no CORS) ---------------
  getEnrich: (indicator) => http.get(`/api/v1/enrich/${encodeURIComponent(indicator)}`),

  // --- state-changing operations (Bearer token required) -------------------
  processText: (text) => http.post('/api/v1/process', { text }, withAuth()),
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
