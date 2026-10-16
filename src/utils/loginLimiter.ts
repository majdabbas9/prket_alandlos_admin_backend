// Brute-force protection for /auth/login: counts failed logins per client IP and per username in a
// fixed window, and blocks further attempts (before any bcrypt work) once either limit is hit.
// Each attempt is counted before the password check and refunded if it succeeds, so a burst of
// parallel requests can't all slip past the limit while their bcrypt compares are running.
// In memory is enough: the Worker runs a single container (max_instances: 1). The per-username
// limit is higher so a single attacker can't lock the admin out as easily, but it still caps
// guessing spread over many IPs.

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES_PER_IP = 10;
const MAX_FAILURES_PER_USERNAME = 30;
// Expired entries are swept once the map grows past this, so it can't grow without bound
const SWEEP_THRESHOLD = 10_000;

type Entry = { count: number; resetAt: number };
const failures = new Map<string, Entry>();

const keysFor = (ip: string, username: string) => ({
  ipKey: `ip:${ip}`,
  userKey: `user:${username.toLowerCase()}`,
});

const activeEntry = (key: string, now: number): Entry | undefined => {
  const entry = failures.get(key);
  if (entry && entry.resetAt <= now) {
    failures.delete(key);
    return undefined;
  }
  return entry;
};

/** Seconds until another login attempt is allowed, or 0 if it is allowed now. */
export const loginRetryAfter = (ip: string, username: string): number => {
  const now = Date.now();
  const { ipKey, userKey } = keysFor(ip, username);
  const blocked = [
    [activeEntry(ipKey, now), MAX_FAILURES_PER_IP],
    [activeEntry(userKey, now), MAX_FAILURES_PER_USERNAME],
  ] as const;
  const resetAt = Math.max(
    0,
    ...blocked.filter(([e, max]) => e && e.count >= max).map(([e]) => e!.resetAt),
  );
  return resetAt ? Math.ceil((resetAt - now) / 1000) : 0;
};

export const recordLoginAttempt = (ip: string, username: string): void => {
  const now = Date.now();
  if (failures.size > SWEEP_THRESHOLD) {
    for (const [key, entry] of failures) if (entry.resetAt <= now) failures.delete(key);
  }
  const { ipKey, userKey } = keysFor(ip, username);
  for (const key of [ipKey, userKey]) {
    const entry = activeEntry(key, now);
    if (entry) entry.count += 1;
    else failures.set(key, { count: 1, resetAt: now + WINDOW_MS });
  }
};

/** A successful login clears its IP's count and refunds the attempt on the username. */
export const recordLoginSuccess = (ip: string, username: string): void => {
  const { ipKey, userKey } = keysFor(ip, username);
  failures.delete(ipKey);
  const entry = activeEntry(userKey, Date.now());
  if (entry && entry.count > 0) entry.count -= 1;
};

/** Tests only. */
export const resetLoginLimiter = (): void => failures.clear();

export const LOGIN_LIMITS = { WINDOW_MS, MAX_FAILURES_PER_IP, MAX_FAILURES_PER_USERNAME };
