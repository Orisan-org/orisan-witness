/**
 * Backup monitoring: making a backup that STOPS RUNNING a loud event.
 *
 * The failure this is built for is silence. A backup loop that throws once a
 * night into a log nobody reads, or a machine that is quietly gone, both look
 * exactly like a healthy service right up until the restore. So there are two
 * signals, deliberately of opposite kinds:
 *
 *  1. `GET /v1/backup-status` — this process reporting on itself. 503 when the
 *     last success is too old, when the last run failed, or when there is no
 *     off-box destination configured at all. Useful, but it can only fire while
 *     the process is alive to answer.
 *
 *  2. A dead-man's-switch heartbeat: after every SUCCESSFUL backup we ping
 *     WITNESS_BACKUP_HEARTBEAT_URL. The alert is the ABSENCE of that ping,
 *     raised by something that is not us. This is the one that survives the
 *     machine being destroyed, the volume being lost, or the process wedging —
 *     precisely the cases where an alert generated on-box never arrives.
 *
 * WHY /health IS NOT USED FOR THIS. Fly's http_service check polls /health and
 * will restart, and eventually refuse to route to, a machine that fails it.
 * Wiring backup freshness into /health would mean a broken bucket takes the
 * witness OFFLINE — and an unreachable witness makes every customer's `verify`
 * return exit 2 "cannot verify". Degrading the product's core promise because
 * a backup is late is a strictly worse outcome than a late backup. /health
 * stays liveness-only; backup health gets its own endpoint on purpose.
 */

import type { BackupOutcome } from './backup.js';

export const DEFAULT_MAX_AGE_SECONDS = 26 * 60 * 60;
export const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;

export type BackupState = 'ok' | 'never_run' | 'stale' | 'failing' | 'not_configured' | 'on_data_volume';

export interface BackupStatus {
  ok: boolean;
  state: BackupState;
  detail: string;
  target: string | null;
  last_success_at: string | null;
  last_success_age_seconds: number | null;
  last_failure_at: string | null;
  last_error: string | null;
  consecutive_failures: number;
  max_age_seconds: number;
  heartbeat_configured: boolean;
  last_backup: { stamp: string; bytes: number; sha256: string; read_back: string; pruned: number } | null;
}

export interface MonitorOptions {
  /** null when no off-box destination is configured. */
  target: string | null;
  /** Set when the configured destination sits on the database volume. */
  onDataVolume?: boolean;
  /** Why there is no target, reported verbatim so the fix is obvious. */
  unconfiguredReason?: string;
  maxAgeSeconds?: number;
  heartbeatUrl?: string;
  now?: () => number;
  log?: (e: Record<string, unknown>) => void;
  fetchImpl?: typeof fetch;
}

export class BackupMonitor {
  private lastSuccess: { at: number; outcome: BackupOutcome } | null = null;
  private lastFailure: { at: number; error: string } | null = null;
  private failures = 0;
  private readonly now: () => number;
  private readonly log: (e: Record<string, unknown>) => void;

  constructor(private readonly opts: MonitorOptions) {
    this.now = opts.now ?? Date.now;
    this.log = opts.log ?? ((e) => process.stdout.write(`${JSON.stringify(e)}\n`));
  }

  get maxAgeSeconds(): number { return this.opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS; }

  recordSuccess(outcome: BackupOutcome): void {
    this.lastSuccess = { at: this.now(), outcome };
    this.failures = 0;
    this.log({
      ts: new Date(this.now()).toISOString(), msg: 'backup written',
      target: outcome.target, key: outcome.dbKey, bytes: outcome.bytes,
      sha256: outcome.sha256, read_back: outcome.readBack, pruned: outcome.pruned.length,
    });
    void this.heartbeat('');
  }

  recordFailure(error: string): void {
    this.lastFailure = { at: this.now(), error };
    this.failures++;
    // `alert: true` is the field the log drain filters on. A backup failure is
    // never a debug-level event: every one of them is a step closer to having
    // no history to restore.
    this.log({
      ts: new Date(this.now()).toISOString(), msg: 'BACKUP FAILED', alert: true,
      error, consecutive_failures: this.failures, target: this.opts.target,
    });
    void this.heartbeat('/fail');
  }

  /** healthchecks.io-style: bare URL for success, `/fail` suffix for failure. */
  private async heartbeat(suffix: string): Promise<void> {
    const url = this.opts.heartbeatUrl;
    if (!url) return;
    const f = this.opts.fetchImpl ?? fetch;
    try {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 10_000);
      try { await f(`${url.replace(/\/$/, '')}${suffix}`, { method: 'POST', signal: ac.signal }); }
      finally { clearTimeout(t); }
    } catch (e) {
      // Never let the alerting path take down the thing it is watching.
      this.log({ ts: new Date(this.now()).toISOString(), msg: 'heartbeat ping failed', error: (e as Error).message });
    }
  }

  status(): BackupStatus {
    const t = this.now();
    const ageS = this.lastSuccess ? Math.floor((t - this.lastSuccess.at) / 1000) : null;
    const base = {
      target: this.opts.target,
      last_success_at: this.lastSuccess ? new Date(this.lastSuccess.at).toISOString() : null,
      last_success_age_seconds: ageS,
      last_failure_at: this.lastFailure ? new Date(this.lastFailure.at).toISOString() : null,
      last_error: this.lastFailure?.error ?? null,
      consecutive_failures: this.failures,
      max_age_seconds: this.maxAgeSeconds,
      heartbeat_configured: Boolean(this.opts.heartbeatUrl),
      last_backup: this.lastSuccess
        ? {
            stamp: this.lastSuccess.outcome.stamp,
            bytes: this.lastSuccess.outcome.bytes,
            sha256: this.lastSuccess.outcome.sha256,
            read_back: this.lastSuccess.outcome.readBack,
            pruned: this.lastSuccess.outcome.pruned.length,
          }
        : null,
    };

    // Ordered by what an operator should fix first. "No destination" outranks
    // "late", because nothing being configured is not a transient condition.
    if (!this.opts.target) {
      return { ...base, ok: false, state: 'not_configured',
        detail: this.opts.unconfiguredReason ?? 'no backup destination is configured; nothing is being backed up' };
    }
    if (this.opts.onDataVolume) {
      return { ...base, ok: false, state: 'on_data_volume',
        detail: `backups are being written to ${this.opts.target}, which is on the database volume: losing the volume loses both` };
    }
    if (this.failures > 0) {
      return { ...base, ok: false, state: 'failing',
        detail: `${this.failures} consecutive backup failure(s); last error: ${this.lastFailure?.error ?? 'unknown'}` };
    }
    if (!this.lastSuccess) {
      return { ...base, ok: false, state: 'never_run', detail: 'no backup has completed since this process started' };
    }
    if (ageS !== null && ageS > this.maxAgeSeconds) {
      return { ...base, ok: false, state: 'stale',
        detail: `last successful backup was ${ageS}s ago, over the ${this.maxAgeSeconds}s limit` };
    }
    return { ...base, ok: true, state: 'ok', detail: `last successful backup ${ageS}s ago to ${this.opts.target}` };
  }
}

export interface BackupSchedule { stop: () => void; runNow: () => Promise<void> }

/**
 * Run `job` now and then every `intervalMs`.
 *
 * One immediately on boot, because a process that has never taken a backup is
 * the one most likely to need one, and because a misconfigured bucket should
 * announce itself at deploy time rather than at 03:00 tomorrow.
 */
export function scheduleBackups(
  job: () => Promise<BackupOutcome>,
  monitor: BackupMonitor,
  intervalMs = DEFAULT_INTERVAL_MS,
): BackupSchedule {
  let running = false;
  const tick = async (): Promise<void> => {
    if (running) return; // a slow upload must not overlap the next tick
    running = true;
    try { monitor.recordSuccess(await job()); }
    catch (e) { monitor.recordFailure((e as Error).message); }
    finally { running = false; }
  };
  void tick();
  const timer = setInterval(() => void tick(), intervalMs);
  timer.unref();
  return { stop: () => clearInterval(timer), runNow: tick };
}
