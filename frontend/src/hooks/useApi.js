// -----------------------------------------------------------------------------
// Data-fetching hooks.
//
//   useApi(fetcher, { deps, auto, refreshMs })
//     - runs `fetcher()` (a function returning a promise of parsed data)
//     - auto-runs on mount and whenever `deps` change
//     - optional polling when `refreshMs` is set (live dashboard widgets)
//     - exposes `reload()`, `setData`, `loading`, `error`
//
//   useAsync(fn)
//     - for one-shot actions (e.g. POST /api/v1/process): returns `run`,
//       `loading`, `error`, `data`
// -----------------------------------------------------------------------------

import { useCallback, useEffect, useRef, useState } from 'react';

export function useApi(fetcher, { deps = [], auto = true, refreshMs = 0 } = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(auto);
  const [error, setError] = useState(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  // Keep deps stable reference for the effect only; actual change detection is
  // delegated to the caller's deps array.
  const depsKey = JSON.stringify(deps);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetcherRef.current();
      setData(result);
      return result;
    } catch (err) {
      setError(err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!auto) return undefined;
    load();
    if (refreshMs > 0) {
      const id = setInterval(load, refreshMs);
      return () => clearInterval(id);
    }
    return undefined;
  }, [load, depsKey, auto, refreshMs]);

  return { data, loading, error, reload: load, setData };
}

export function useAsync(fn) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const result = await fnRef.current(...args);
      setData(result);
      return result;
    } catch (err) {
      setError(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { data, loading, error, run, setData, setError };
}
