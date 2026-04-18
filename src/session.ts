import type { ExchangeResult, SessionData, SessionValidationResult } from "../contracts";
export type { ExchangeResult, SessionData, SessionValidationResult };

export const SESSION_DURATION = 60 * 60; // 1 hour in seconds
const STATE_TTL = 60 * 10; // 10 minutes
const EXCHANGE_CODE_TTL = 60; // seconds — long enough for the redirect round-trip, short enough to limit leak window

interface OAuthState {
  codeVerifier: string;
  redirectUrl: string;
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
  userData: Omit<SessionData, "createdAt" | "expiresAt">,
): Promise<{ sessionId: string; expiresInSeconds: number }> {
  const sessionId = generateSessionId();
  const now = Math.floor(Date.now() / 1000);

  const session: SessionData = {
    ...userData,
    createdAt: now,
    expiresAt: now + SESSION_DURATION,
  };

  await kv.put(`session:${sessionId}`, JSON.stringify(session), {
    expirationTtl: SESSION_DURATION,
  });

  // Best-effort: sync user data to other sessions; failure must not block login
  try {
    await updateUserSessions(kv, sessionId, userData);
  } catch (e) {
    console.error(`Failed to update user sessions for user:${userData.userId}`, String(e));
  }

  return { sessionId, expiresInSeconds: SESSION_DURATION };
}

async function updateUserSessions(
  kv: KVNamespace,
  newSessionId: string,
  userData: Omit<SessionData, "createdAt" | "expiresAt">,
): Promise<void> {
  const userKey = `user:${userData.userId}`;
  const raw = await kv.get(userKey);

  let sessionIds: string[];
  try {
    sessionIds = raw ? JSON.parse(raw) : [];
  } catch (e) {
    console.error(`Corrupted user session index for ${userKey}`, String(e));
    sessionIds = [];
  }

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

  // User index TTL resets to SESSION_DURATION since the newest session was just created
  await kv.put(userKey, JSON.stringify(activeIds), {
    expirationTtl: SESSION_DURATION,
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
    const raw = await kv.get(userKey);
    if (raw) {
      let sessionIds: string[];
      try {
        sessionIds = JSON.parse(raw);
      } catch (e) {
        console.error(`Corrupted user session index for ${userKey}`, String(e));
        sessionIds = [];
      }
      const filtered = sessionIds.filter((id) => id !== sessionId);
      if (filtered.length > 0) {
        await kv.put(userKey, JSON.stringify(filtered), { expirationTtl: SESSION_DURATION });
      } else {
        await kv.delete(userKey);
      }
    }
  }
  await kv.delete(`session:${sessionId}`);
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
): Promise<void> {
  const data: OAuthState = { codeVerifier, redirectUrl };
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
