import type { ExchangeResult, SessionData, SessionValidationResult } from "../contracts";
export type { ExchangeResult, SessionData, SessionValidationResult };

export const SESSION_DURATION = 60 * 60; // 1 hour in seconds
export const DEVICE_SESSION_DURATION = 60 * 60 * 24 * 90;
const DEVICE_SLIDE_INTERVAL = 60 * 60 * 24; // bounds a device session to one KV write per day
// The index must outlive its longest session; every device-session extension refreshes it.
const USER_INDEX_TTL = DEVICE_SESSION_DURATION;
const STATE_TTL = 60 * 10; // 10 minutes
const EXCHANGE_CODE_TTL = 60; // seconds — long enough for the redirect round-trip, short enough to limit leak window

interface OAuthState {
  codeVerifier: string;
  redirectUrl: string;
  /** Set for native-app logins; `redirectUrl` is then the allowlisted app URI, never request input. */
  challenge?: string;
}

interface DeviceExchange extends ExchangeResult {
  challenge: string;
}

function generateRandomHex(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const generateSessionId = generateRandomHex;
export const generateExchangeCode = generateRandomHex;

export async function createSession(
  kv: KVNamespace,
  userData: Omit<SessionData, "createdAt" | "expiresAt" | "device">,
  device = false,
): Promise<ExchangeResult> {
  const sessionId = generateSessionId();
  const now = Math.floor(Date.now() / 1000);
  const duration = device ? DEVICE_SESSION_DURATION : SESSION_DURATION;

  const session: SessionData = {
    ...userData,
    ...(device && { device: true }),
    createdAt: now,
    expiresAt: now + duration,
  };

  await kv.put(`session:${sessionId}`, JSON.stringify(session), {
    expirationTtl: duration,
  });

  // Best-effort: sync user data to other sessions; failure must not block login
  try {
    await updateUserSessions(kv, sessionId, userData);
  } catch (e) {
    console.error(`Failed to update user sessions for user:${userData.userId}`, String(e));
  }

  return { sessionId, expiresInSeconds: duration };
}

async function readUserIndex(kv: KVNamespace, userKey: string): Promise<string[]> {
  const raw = await kv.get(userKey);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error(`Corrupted user session index for ${userKey}`, String(e));
    return [];
  }
}

async function updateUserSessions(
  kv: KVNamespace,
  newSessionId: string,
  userData: Omit<SessionData, "createdAt" | "expiresAt" | "device">,
): Promise<void> {
  const userKey = `user:${userData.userId}`;
  const sessionIds = await readUserIndex(kv, userKey);

  // Update existing sessions with latest user data, remove expired ones
  const activeIds: string[] = [newSessionId];
  const results = await Promise.allSettled(
    sessionIds.map(async (id) => {
      if (id === newSessionId) return;
      const existing = await getSession(kv, id);
      if (!existing) return;

      activeIds.push(id);
      const updated: SessionData = {
        ...existing,
        email: userData.email,
        groups: userData.groups,
        userName: userData.userName,
      };
      const remainingTtl = existing.expiresAt - Math.floor(Date.now() / 1000);
      if (remainingTtl > 0) {
        await kv.put(`session:${id}`, JSON.stringify(updated), {
          expirationTtl: remainingTtl,
        });
      }
    }),
  );

  for (const result of results) {
    if (result.status === "rejected") {
      console.error("Failed to update a user session", String(result.reason));
    }
  }

  await kv.put(userKey, JSON.stringify(activeIds), {
    expirationTtl: USER_INDEX_TTL,
  });
}

export async function getSession(kv: KVNamespace, sessionId: string): Promise<SessionData | null> {
  const raw = await kv.get(`session:${sessionId}`);
  if (!raw) return null;

  try {
    return JSON.parse(raw) as SessionData;
  } catch (e) {
    console.error(`Failed to parse session data for session:${sessionId}`, String(e));
    return null;
  }
}

export async function deleteSession(kv: KVNamespace, sessionId: string): Promise<void> {
  // Remove from user index before deleting the session itself
  const session = await getSession(kv, sessionId);
  if (session) {
    const userKey = `user:${session.userId}`;
    const sessionIds = await readUserIndex(kv, userKey);
    if (sessionIds.length > 0) {
      const filtered = sessionIds.filter((id) => id !== sessionId);
      if (filtered.length > 0) {
        await kv.put(userKey, JSON.stringify(filtered), { expirationTtl: USER_INDEX_TTL });
      } else {
        await kv.delete(userKey);
      }
    }
  }
  await kv.delete(`session:${sessionId}`);
}

export async function deleteUserSessions(kv: KVNamespace, userId: string): Promise<void> {
  const userKey = `user:${userId}`;
  const sessionIds = await readUserIndex(kv, userKey);
  await Promise.all(sessionIds.map((id) => kv.delete(`session:${id}`)));
  await kv.delete(userKey);
}

// OR logic: user must belong to at least one of the required groups
export function validateSession(
  session: SessionData | null,
  requiredGroups?: string[],
): SessionValidationResult {
  if (!session) return { valid: false, session: null };

  const now = Math.floor(Date.now() / 1000);
  if (session.expiresAt < now) return { valid: false, session: null };

  if (requiredGroups && requiredGroups.length > 0) {
    const hasGroup = session.groups.some((g) => requiredGroups.includes(g));
    if (!hasGroup) return { valid: false, session: null };
  }

  return { valid: true, session };
}

// Device sessions slide: a validation more than a day after the last extension renews the 90 days.
export async function validateAndSlideSession(
  kv: KVNamespace,
  sessionId: string,
  requiredGroups?: string[],
): Promise<SessionValidationResult> {
  const result = validateSession(await getSession(kv, sessionId), requiredGroups);
  if (!result.valid || !result.session.device) return result;

  const now = Math.floor(Date.now() / 1000);
  if (result.session.expiresAt - now > DEVICE_SESSION_DURATION - DEVICE_SLIDE_INTERVAL) {
    return result;
  }

  const extended: SessionData = { ...result.session, expiresAt: now + DEVICE_SESSION_DURATION };
  try {
    await kv.put(`session:${sessionId}`, JSON.stringify(extended), {
      expirationTtl: DEVICE_SESSION_DURATION,
    });
    const userKey = `user:${extended.userId}`;
    const sessionIds = await readUserIndex(kv, userKey);
    if (!sessionIds.includes(sessionId)) sessionIds.push(sessionId);
    await kv.put(userKey, JSON.stringify(sessionIds), { expirationTtl: USER_INDEX_TTL });
  } catch (e) {
    console.error(`Failed to extend device session ${sessionId}`, String(e));
    return result;
  }
  return { valid: true, session: extended };
}

// Single-use JSON read: parse, then best-effort delete so replays fail. TTL is the backstop if delete fails.
async function consumeKvJson<T>(kv: KVNamespace, key: string): Promise<T | null> {
  const raw = await kv.get(key);
  if (!raw) return null;

  let data: T;
  try {
    data = JSON.parse(raw) as T;
  } catch (e) {
    console.error(`Failed to parse KV JSON for ${key}`, String(e));
    return null;
  }

  try {
    await kv.delete(key);
  } catch (e) {
    console.error(`Failed to delete consumed KV entry ${key}`, String(e));
  }

  return data;
}

export async function storeOAuthState(
  kv: KVNamespace,
  state: string,
  codeVerifier: string,
  redirectUrl: string,
  challenge?: string,
): Promise<void> {
  const data: OAuthState = { codeVerifier, redirectUrl, challenge };
  await kv.put(`oauth:${state}`, JSON.stringify(data), { expirationTtl: STATE_TTL });
}

export async function consumeOAuthState(
  kv: KVNamespace,
  state: string,
): Promise<OAuthState | null> {
  return consumeKvJson<OAuthState>(kv, `oauth:${state}`);
}

export async function storeExchangeCode(
  kv: KVNamespace,
  code: string,
  data: ExchangeResult,
): Promise<void> {
  await kv.put(`exchange:${code}`, JSON.stringify(data), { expirationTtl: EXCHANGE_CODE_TTL });
}

export async function consumeExchangeCode(
  kv: KVNamespace,
  code: string,
): Promise<ExchangeResult | null> {
  return consumeKvJson<ExchangeResult>(kv, `exchange:${code}`);
}

// A separate key prefix keeps challenge-bound codes out of `exchangeAuthCode` and web codes out of `/token`.
export async function storeDeviceExchangeCode(
  kv: KVNamespace,
  code: string,
  data: ExchangeResult,
  challenge: string,
): Promise<void> {
  const entry: DeviceExchange = { ...data, challenge };
  await kv.put(`device-exchange:${code}`, JSON.stringify(entry), {
    expirationTtl: EXCHANGE_CODE_TTL,
  });
}

// The code is burned before the verifier is checked, so a wrong guess cannot be retried.
export async function consumeDeviceExchangeCode(
  kv: KVNamespace,
  code: string,
  codeVerifier: string,
): Promise<ExchangeResult | null> {
  const entry = await consumeKvJson<DeviceExchange>(kv, `device-exchange:${code}`);
  if (!entry) return null;

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  if (challenge !== entry.challenge) return null;

  return { sessionId: entry.sessionId, expiresInSeconds: entry.expiresInSeconds };
}
