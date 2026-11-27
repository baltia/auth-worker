import { afterEach, beforeEach, describe, expect, setSystemTime, test } from "bun:test";

import {
  consumeDeviceExchangeCode,
  consumeExchangeCode,
  createSession,
  deleteSession,
  deleteUserSessions,
  DEVICE_SESSION_DURATION,
  getSession,
  SESSION_DURATION,
  storeDeviceExchangeCode,
  storeExchangeCode,
  validateAndSlideSession,
} from "./src/session";

const DAY = 60 * 60 * 24;
const T0 = Date.parse("2026-01-01T00:00:00Z");
const at = (seconds: number) => setSystemTime(new Date(T0 + seconds * 1000));

function fakeKv() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number | undefined>();
  const kv = {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
      store.set(key, value);
      ttls.set(key, opts?.expirationTtl);
    },
    delete: async (key: string) => {
      store.delete(key);
      ttls.delete(key);
    },
  };
  return { kv: kv as unknown as KVNamespace, store, ttls, put: kv.put };
}

const user = { userId: "u1", userName: "Ada", accessToken: "t", groups: ["users"] };

async function challengeOf(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return Buffer.from(digest).toString("base64url");
}

afterEach(() => setSystemTime());
beforeEach(() => at(0));

describe("device session sliding", () => {
  test("extends only after a day, and only device sessions", async () => {
    const { kv, ttls } = fakeKv();
    const device = await createSession(kv, user, true);
    const web = await createSession(kv, user);
    expect(device.expiresInSeconds).toBe(DEVICE_SESSION_DURATION);
    expect(web.expiresInSeconds).toBe(SESSION_DURATION);

    const created = (await getSession(kv, device.sessionId))!.expiresAt;

    at(DAY - 60);
    await validateAndSlideSession(kv, device.sessionId);
    expect((await getSession(kv, device.sessionId))!.expiresAt).toBe(created);

    at(DAY + 60);
    const result = await validateAndSlideSession(kv, device.sessionId);
    const extended = (await getSession(kv, device.sessionId))!.expiresAt;
    expect(extended).toBe(Math.floor(T0 / 1000) + DAY + 60 + DEVICE_SESSION_DURATION);
    expect(result.valid && result.session.expiresAt).toBe(extended);
    expect(ttls.get(`session:${device.sessionId}`)).toBe(DEVICE_SESSION_DURATION);

    const webBefore = (await getSession(kv, web.sessionId))!.expiresAt;
    await validateAndSlideSession(kv, web.sessionId);
    expect((await getSession(kv, web.sessionId))!.expiresAt).toBe(webBefore);
  });

  test("an extension refreshes the user index TTL", async () => {
    const { kv, ttls } = fakeKv();
    const device = await createSession(kv, user, true);
    ttls.set("user:u1", 5);
    at(2 * DAY);
    await validateAndSlideSession(kv, device.sessionId);
    expect(ttls.get("user:u1")).toBe(DEVICE_SESSION_DURATION);
  });

  test("an invalid group is not extended", async () => {
    const { kv } = fakeKv();
    const device = await createSession(kv, user, true);
    at(2 * DAY);
    expect((await validateAndSlideSession(kv, device.sessionId, ["admins"])).valid).toBe(false);
    expect((await getSession(kv, device.sessionId))!.expiresAt).toBe(
      Math.floor(T0 / 1000) + DEVICE_SESSION_DURATION,
    );
  });
});

describe("user index", () => {
  test("outlives a device session after login and logout", async () => {
    const { kv, ttls } = fakeKv();
    const device = await createSession(kv, user, true);
    expect(ttls.get("user:u1")).toBe(DEVICE_SESSION_DURATION);

    const web = await createSession(kv, user);
    await deleteSession(kv, web.sessionId);
    expect(ttls.get("user:u1")).toBe(DEVICE_SESSION_DURATION);
    expect(await getSession(kv, device.sessionId)).not.toBeNull();
  });

  test("deleteUserSessions signs out every device", async () => {
    const { kv, store } = fakeKv();
    const a = await createSession(kv, user, true);
    const b = await createSession(kv, user);
    const other = await createSession(kv, { ...user, userId: "u2" });
    await deleteUserSessions(kv, "u1");
    expect(await getSession(kv, a.sessionId)).toBeNull();
    expect(await getSession(kv, b.sessionId)).toBeNull();
    expect(store.has("user:u1")).toBe(false);
    expect(await getSession(kv, other.sessionId)).not.toBeNull();
  });
});

describe("device exchange codes", () => {
  const verifier = "a".repeat(43);
  const result = { sessionId: "s1", expiresInSeconds: DEVICE_SESSION_DURATION };

  test("redeemable once, with the right verifier", async () => {
    const { kv } = fakeKv();
    await storeDeviceExchangeCode(kv, "c1", result, await challengeOf(verifier));
    expect(await consumeDeviceExchangeCode(kv, "c1", verifier)).toEqual(result);
    expect(await consumeDeviceExchangeCode(kv, "c1", verifier)).toBeNull();
  });

  test("a wrong verifier fails and burns the code", async () => {
    const { kv } = fakeKv();
    await storeDeviceExchangeCode(kv, "c1", result, await challengeOf(verifier));
    expect(await consumeDeviceExchangeCode(kv, "c1", "b".repeat(43))).toBeNull();
    expect(await consumeDeviceExchangeCode(kv, "c1", verifier)).toBeNull();
  });

  test("the two code kinds are not interchangeable", async () => {
    const { kv } = fakeKv();
    await storeDeviceExchangeCode(kv, "dev", result, await challengeOf(verifier));
    await storeExchangeCode(kv, "web", result);
    expect(await consumeExchangeCode(kv, "dev")).toBeNull();
    expect(await consumeDeviceExchangeCode(kv, "web", verifier)).toBeNull();
  });
});
