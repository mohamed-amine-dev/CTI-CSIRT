import React, { useState } from 'react';
import {
  AlertTriangle, Mail, PlayCircle, Plus, RefreshCw, Send, Trash2,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { Input } from '../components/ui/input';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select';
import { Switch } from '../components/ui/switch';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';

const FREQ_LABEL = { daily: 'Daily', every_2_days: 'Every 2 days' };

/**
 * DigestSettings — admin-only management of the CSIRT daily-email digest.
 *
 * There is deliberately NO public sign-up: recipients can only be added or
 * changed here (or via tools/manage_digest_recipients.py), and every call goes
 * through the backend `require_admin` RBAC gate. The page also exposes the
 * real "send test" and "run due digests now" actions so an admin can verify
 * delivery without waiting for the daily schedule.
 */
export default function DigestSettings() {
  const recipients = useApi(() => unwrap(api.getDigestRecipients()));
  const status = useApi(() => unwrap(api.getDigestStatus()));

  const [email, setEmail] = useState('');
  const [frequency, setFrequency] = useState('daily');
  const [testEmail, setTestEmail] = useState('');
  const [notice, setNotice] = useState('');

  const addRecipient = useAsync((addr, freq) => unwrap(api.addDigestRecipient(addr, freq, true)));
  const updateRecipient = useAsync((addr, patch) => unwrap(api.updateDigestRecipient(addr, patch)));
  const deleteRecipient = useAsync((addr) => unwrap(api.deleteDigestRecipient(addr)));
  const runNow = useAsync(() => unwrap(api.runDigestNow()));
  const sendTest = useAsync((addr) => unwrap(api.sendDigestTest(addr, 1)));

  const reload = () => {
    recipients.reload();
    status.reload();
  };

  const submitAdd = async (e) => {
    e.preventDefault();
    setNotice('');
    if (!email.trim()) return;
    try {
      await addRecipient.run(email.trim(), frequency);
      setEmail('');
      reload();
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const changeFrequency = async (addr, freq) => {
    try {
      await updateRecipient.run(addr, { frequency: freq });
      reload();
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const toggleEnabled = async (addr, enabled) => {
    try {
      await updateRecipient.run(addr, { enabled });
      reload();
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const remove = async (addr) => {
    if (!window.confirm(`Remove ${addr} from the digest list?`)) return;
    try {
      await deleteRecipient.run(addr);
      reload();
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const runDue = async () => {
    setNotice('');
    try {
      const res = await runNow.run();
      setNotice(`Run complete — due: ${res.due}, sent: ${res.sent}, failed: ${res.failed}.`);
      reload();
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const submitTest = async (e) => {
    e.preventDefault();
    setNotice('');
    if (!testEmail.trim()) return;
    try {
      await sendTest.run(testEmail.trim());
      setNotice(`Test digest sent to ${testEmail.trim()}.`);
    } catch (err) {
      setNotice(errorText(err));
    }
  };

  const s = status.data;
  const items = recipients.data?.items || [];
  const accessDenied = recipients.error?.response?.status === 403 || status.error?.response?.status === 403;

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-xl font-bold text-ink">Daily Email Digest</h1>
        <p className="text-sm text-dim">
          Scheduled threat-intelligence summary emailed to the CSIRT team. Each
          recipient has its own cadence; disabled recipients receive nothing.
          Admin-managed — there is no public sign-up.
        </p>
      </header>

      {accessDenied && (
        <ErrorState message="Administrator access required. Sign in with an admin token to manage the digest." />
      )}
      {!accessDenied && recipients.error && <ErrorState message={errorText(recipients.error)} />}
      {!accessDenied && status.error && <ErrorState message={errorText(status.error)} />}

      {/* ---------- Status --------------------------------------------------- */}
      {s && (
        <Card title="Delivery status" subtitle="SMTP is configured in .env" icon={Mail}>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <Badge tone={s.smtp_configured ? 'blue' : 'neutral'}>
              {s.smtp_configured ? 'SMTP configured' : 'SMTP not configured'}
            </Badge>
            <Badge tone={s.digest_enabled ? 'blue' : 'neutral'}>
              {s.digest_enabled ? 'Scheduler on' : 'Scheduler off'}
            </Badge>
            <span className="text-dim">
              Sends daily around <strong className="text-ink">{String(s.digest_hour_utc).padStart(2, '0')}:00 UTC</strong>
            </span>
            {s.from_address && (
              <span className="text-dim">From <code className="rounded bg-raised px-1 text-[11px]">{s.from_address}</code></span>
            )}
            <span className="text-dim">
              <strong className="text-ink">{s.recipients_total}</strong> recipient(s) ·{' '}
              <strong className="text-ink">{s.recipients_due}</strong> due now
            </span>
          </div>
          {!s.smtp_configured && (
            <p className="mt-3 flex items-center gap-2 text-xs text-amber-400">
              <AlertTriangle size={14} />
              Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM in .env, then restart the app.
            </p>
          )}
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button
              variant="secondary" size="sm" icon={PlayCircle}
              onClick={runDue} loading={runNow.loading} disabled={!s.smtp_configured}
            >
              Run due digests now
            </Button>
            <form onSubmit={submitTest} className="flex items-center gap-2">
              <Input
                type="email" value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="test@example.org"
                className="h-7 w-56 text-xs"
              />
              <Button
                type="submit" variant="outline" size="sm" icon={Send}
                loading={sendTest.loading} disabled={!s.smtp_configured}
              >
                Send test digest
              </Button>
            </form>
          </div>
        </Card>
      )}

      {notice && (
        <p className="rounded-lg border border-line bg-base/60 px-3 py-2 text-xs text-dim">{notice}</p>
      )}

      <div className="grid gap-4 xl:grid-cols-5">
        {/* ---------- Add recipient ----------------------------------------- */}
        <Card className="xl:col-span-2" title="Add recipient" subtitle="Admin-only — no public sign-up" icon={Plus}>
          <form onSubmit={submitAdd} className="flex flex-col gap-3">
            <Input
              type="email" value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@example.org"
            />
            <Select value={frequency} onValueChange={setFrequency}>
              <SelectTrigger>
                <SelectValue placeholder="Cadence" />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(FREQ_LABEL).map(([value, label]) => (
                  <SelectItem key={value} value={value}>{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button type="submit" variant="primary" size="sm" icon={Plus} loading={addRecipient.loading} className="self-start">
              Add recipient
            </Button>
          </form>
        </Card>

        {/* ---------- Recipients -------------------------------------------- */}
        <Card
          className="xl:col-span-3"
          title="Recipients"
          subtitle="Cadence and enable state apply immediately"
          icon={Mail}
          actions={
            <Button variant="ghost" size="sm" icon={RefreshCw} onClick={reload} loading={recipients.loading}>
              Refresh
            </Button>
          }
        >
          <div className="flex flex-col gap-2">
            {!recipients.loading && items.length === 0 && !recipients.error && (
              <EmptyState
                icon={Mail}
                title="No recipients yet"
                message="Add the CSIRT team members who should receive the digest. Nothing is ever sent to an address that is not listed here."
              />
            )}
            {items.map((r) => (
              <div key={r.email} className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-base/60 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-[13px] text-ink">{r.email}</p>
                  <p className="text-[11px] text-dim">
                    Last sent: {r.last_sent_at || 'never'}
                    {r.added_by ? ` · added by ${r.added_by}` : ''}
                  </p>
                </div>
                {r.due_now && <Badge tone="blue">Due</Badge>}
                <Select value={r.frequency} onValueChange={(v) => changeFrequency(r.email, v)}>
                  <SelectTrigger className="h-7 w-36 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(FREQ_LABEL).map(([value, label]) => (
                      <SelectItem key={value} value={value}>{label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={r.enabled}
                    onCheckedChange={(v) => toggleEnabled(r.email, v)}
                    aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.email}`}
                  />
                  <span className="text-[11px] text-dim">{r.enabled ? 'Enabled' : 'Disabled'}</span>
                </div>
                <Button variant="danger" size="sm" icon={Trash2} onClick={() => remove(r.email)} loading={deleteRecipient.loading}>
                  Remove
                </Button>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
