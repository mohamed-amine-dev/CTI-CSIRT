import React, { useEffect, useRef, useState } from 'react';
import { Bell, CheckCheck, Mail, Send } from 'lucide-react';

import { useApi } from '../../hooks/useApi';
import { api, errorText, unwrap } from '../../services/api';
import { severityStyle, timeAgo } from '../../utils/format';

/**
 * NotificationBell — top-bar bell showing the real-time alert feed.
 *
 * Polls the unread count every 15 s for the badge and lazily loads the latest
 * notifications when the panel is opened. Actions (mark read / mark all read /
 * test alert) are Bearer-protected and silently ignored when not configured.
 */
export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [marking, setMarking] = useState(false);
  const panelRef = useRef(null);

  const unread = useApi(() => unwrap(api.getUnreadCount()), { refreshMs: 15_000 });
  const list = useApi(() => unwrap(api.getNotifications({ limit: 10 })), { auto: false });

  // Close when clicking outside the panel.
  useEffect(() => {
    if (!open) return undefined;
    const onDoc = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !list.data) list.reload();
  };

  const markOne = async (id) => {
    try {
      await unwrap(api.markNotificationRead(id));
      list.setData({
        ...list.data,
        items: (list.data?.items || []).map((n) => (n.id === id ? { ...n, read: 1 } : n)),
      });
      unread.reload();
    } catch (e) {
      console.warn('mark read failed:', errorText(e));
    }
  };

  const markAll = async () => {
    setMarking(true);
    try {
      await unwrap(api.markAllNotificationsRead());
      list.setData({ ...list.data, items: (list.data?.items || []).map((n) => ({ ...n, read: 1 })) });
      unread.reload();
    } catch (e) {
      console.warn('mark all read failed:', errorText(e));
    } finally {
      setMarking(false);
    }
  };

  const sendTest = async () => {
    try {
      await unwrap(api.testAlert());
      list.reload();
      unread.reload();
    } catch (e) {
      console.warn('test alert failed:', errorText(e));
    }
  };

  const count = unread.data?.count || 0;
  const items = list.data?.items || [];

  return (
    <div className="relative" ref={panelRef}>
      <button
        onClick={toggle}
        className="relative rounded-lg border border-line bg-surface p-2 text-dim transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
        title="Alerts (Phase 5 real-time notification centre)"
        aria-label="Notifications"
      >
        <Bell size={16} />
        {count > 0 && (
          <span className="absolute -right-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-bold text-white">
            {count > 99 ? '99+' : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-11 z-40 w-[340px] overflow-hidden rounded-xl border border-line bg-surface shadow-2xl">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-faint">
              Alerts {count > 0 && <span className="text-rose-400">({count} new)</span>}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={sendTest}
                className="rounded p-1 text-faint transition-colors hover:text-cyan-300"
                title="Send a test alert (admin)"
              >
                <Send size={13} />
              </button>
              <button
                onClick={markAll}
                disabled={marking || count === 0}
                className="rounded p-1 text-faint transition-colors hover:text-cyan-300 disabled:opacity-40"
                title="Mark all as read"
              >
                <CheckCheck size={14} />
              </button>
            </div>
          </div>

          <div className="max-h-[360px] overflow-y-auto">
            {items.length === 0 ? (
              <p className="px-4 py-8 text-center text-xs text-faint">No alerts yet.</p>
            ) : (
              items.map((n) => (
                <button
                  key={n.id}
                  onClick={() => (n.read ? null : markOne(n.id))}
                  className={`block w-full border-b border-line/60 px-3 py-2.5 text-left transition-colors hover:bg-raised ${
                    n.read ? 'opacity-55' : ''
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`h-2 w-2 shrink-0 rounded-full ${severityStyle(n.severity).badge.match(/text-[\w-]+/)?.[0] || 'bg-cyan-400'}`}
                    />
                    <span className="truncate font-mono text-xs font-semibold text-ink">{n.title}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    {n.cve && <span className="font-mono text-[11px] text-cyan-300">{n.cve}</span>}
                    <span className="rounded border border-line bg-raised px-1 py-px text-[10px] uppercase text-faint">{n.category}</span>
                    <span className="ml-auto flex items-center gap-1 text-[10px] text-faint">
                      {!n.read && <Mail size={10} />}
                      {timeAgo(n.created_at)}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
