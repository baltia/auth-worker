# ssso-auth

> Synology SSO, reduced to a service binding.

A single Cloudflare Worker that wraps Synology's OAuth flow and hands typed sessions to its siblings over RPC. No SDK, no middleware — just one service binding.

- **Deploy:** <https://deploy.workers.cloudflare.com/?url=https://github.com/mastermakrela/ssso-auth-worker>
- **Source:** <https://github.com/mastermakrela/ssso-auth-worker>

---

## 01 / Overview

Synology's DSM can act as an OpenID Connect provider, but wiring it into every Cloudflare Worker you deploy is tedious. **ssso-auth** centralises the OAuth2 + PKCE handshake into one worker and exposes a typed RPC surface (`AuthService`) that sibling workers consume via Service Bindings.

Sessions live in KV. Login mode — cookie or exchange — is picked automatically based on the consumer's origin, so Pages previews and `localhost` work without configuration gymnastics.

## 02 / Capabilities

- **OAuth + PKCE** — Full Synology DSM OIDC flow (login, callback, logout) implemented with [`arctic`](https://arcticjs.dev/). No secrets leak beyond the worker.
- **Typed RPC** — Consumers import `AuthService` types directly from the package and call methods across the binding as if they were local.
- **KV sessions** — Sessions, OAuth state, and single-use exchange codes all live in Workers KV. TTLs handled, no external database.

## 03 / Consume

Add the service binding in the consumer's `wrangler.jsonc`:

```jsonc
"services": [
  { "binding": "AUTH", "service": "ssso-auth", "entrypoint": "AuthService" }
]
```

Install the types (consumer's `package.json`):

```jsonc
"dependencies": {
  "ssso-auth": "github:mastermakrela/ssso-auth-worker"
}
```

Use it from a fetch handler:

```ts
import type { AuthService, SessionData } from "ssso-auth";

export default {
  async fetch(request: Request, env: Env) {
    const sessionId = parseCookie(request.headers.get("Cookie") ?? "", "session_id");
    if (!sessionId) return Response.redirect(env.AUTH.getLoginUrl(request.url), 302);

    const result = await env.AUTH.validateSession(sessionId);
    if (!result.valid) return Response.redirect(env.AUTH.getLoginUrl(request.url), 302);

    // ...handle authenticated request with result.session
  },
};
```

## 04 / Modes

Two login flows, picked automatically by consumer origin:

| Consumer origin                    | Mode         |
| ---------------------------------- | ------------ |
| Same cookie scope as `AUTH_ORIGIN` | **Cookie**   |
| `*.pages.dev`                      | **Exchange** |
| `localhost`, `127.0.0.1`, `[::1]`  | **Exchange** |
| Any other off-domain origin        | **Exchange** |

`AUTH_ORIGIN` can only set cookies for its own parent domain. Consumers outside that domain never see the cookie, so exchange mode hands them a short-lived code they can trade for a session id and set their own cookie.

## 05 / RPC

| Method                                                                  | Purpose                                                                                               |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `validateSession(sessionId, requiredGroups?) → SessionValidationResult` | Verify the session; optionally check group membership (OR logic — user needs at least one).           |
| `getLoginUrl(redirect?) → string`                                       | Build a login URL. `redirect` must match the allowlist, otherwise it falls back to the auth homepage. |
| `exchangeAuthCode(code) → { sessionId, expiresInSeconds } \| null`      | Trade a single-use code for a session id. Codes expire after 60 seconds.                              |
| `deleteSession(sessionId) → void`                                       | Server-side logout. Drops the session from KV.                                                        |

## 06 / Setup

1. **Register an OIDC client in DSM** → SSO Server → OIDC. Redirect URI = `<AUTH_ORIGIN>/callback`. Note the client ID and secret.
2. **Fill the vars** in the worker dashboard (or `wrangler.jsonc` if cloned manually): `BASE_URL`, `CLIENT_ID`, `AUTH_ORIGIN`, optionally `EXTRA_REDIRECT_SUFFIXES`.
3. **Set the secret:** `bunx wrangler secret put CLIENT_PASSWORD`.
4. **Attach a custom domain** to the worker at `AUTH_ORIGIN`.

---

MIT · Cloudflare Workers · Synology DSM · Crafted by [mastermakrela](https://mastermakrela.com/)
