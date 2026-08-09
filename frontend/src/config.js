// -----------------------------------------------------------------------------
// Environment-driven SPA configuration.
// Copy `.env.example` to `.env` to override any of these at build time.
// -----------------------------------------------------------------------------

/** API base URL. Empty string = same origin as the page. In development the
 * Vite proxy forwards `/api` to the FastAPI backend; in production FastAPI
 * serves both the SPA and the API from the same origin. */
export const API_BASE = import.meta.env.VITE_API_BASE || '';

/** Bearer token for state-changing endpoints (POST /api/v1/process, ...).
 * Must match `API_ACCESS_TOKEN` in the backend `.env`. */
export const API_TOKEN = import.meta.env.VITE_API_TOKEN || '';

/** Auto-refresh interval (ms) for the live dashboard views. */
export const REFRESH_MS = 60_000;

/** Page size defaults shared across the list views. */
export const PAGE_SIZE = 20;
