// -----------------------------------------------------------------------------
// Tiny global event bus so the TopBar "Refresh" button can trigger data
// reloads in any mounted page without prop drilling.
// -----------------------------------------------------------------------------

export const REFRESH_EVENT = 'cti:refresh';

export function emitRefresh() {
  window.dispatchEvent(new CustomEvent(REFRESH_EVENT));
}

/** Returns an unsubscribe function; safe to pass straight into useEffect. */
export function onRefresh(cb) {
  window.addEventListener(REFRESH_EVENT, cb);
  return () => window.removeEventListener(REFRESH_EVENT, cb);
}
