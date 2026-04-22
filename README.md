# SSSO Auth Worker

Cloudflare Worker that handles **Synology Single Sign-On** for sibling workers. Consumers connect via service bindings and call typed RPC methods to validate sessions and kick off logins.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mastermakrela/ssso-auth-worker)

- Public OAuth endpoints (`/login`, `/callback`, `/logout`) and a status page at `/`
- `AuthService` — RPC surface exposed to sibling workers via service bindings

## Post-deploy setup

After the Deploy-to-Cloudflare flow finishes:

1. **Register an OIDC client in DSM → SSO Server → OIDC**. Set the redirect URI to `<AUTH_ORIGIN>/callback`. Note the client ID and secret.
2. **Fill the vars** in the worker's dashboard (or in `wrangler.jsonc` if you cloned manually):
   - `BASE_URL` — Synology DSM base URL, e.g. `https://sso.example.com/`
   - `CLIENT_ID` — the OIDC client ID from step 1
   - `AUTH_ORIGIN` — public origin of this worker, e.g. `https://auth.example.com`
   - `EXTRA_REDIRECT_SUFFIXES` — optional, comma-separated
3. **Set the `CLIENT_PASSWORD` secret**: `bunx wrangler secret put CLIENT_PASSWORD`.
4. **Attach a custom domain** to the worker at `AUTH_ORIGIN`.

## Connecting a consumer

Add a service binding in the consumer's `wrangler.jsonc`:

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

Import types:

```ts
import type { AuthService, SessionData } from "ssso-auth";
```

## Two login flows

ssso-auth hands the session back to the consumer in one of two ways. **The server picks automatically** based on the redirect URL:

| Consumer origin                    | Mode used    |
| ---------------------------------- | ------------ |
| Same cookie scope as `AUTH_ORIGIN` | **Cookie**   |
| Pages preview (`*.pages.dev`)      | **Exchange** |
| `localhost` (any port)             | **Exchange** |
| Any other off-domain origin        | **Exchange** |

**Why:** `AUTH_ORIGIN` can only set cookies for its own parent domain. Any consumer outside that domain never sees the cookie, so exchange mode hands it a short-lived code it can trade for a session ID and set its own cookie.

> Examples use a `parseCookie(header, name)` helper — `src/index.ts` has a minimal reference implementation you can copy.

### Cookie mode (default — same-domain consumers)

The auth worker sets `session_id` on the parent domain. The consumer just reads it.

```ts
export default {
  async fetch(request: Request, env: Env) {
    const sessionId = parseCookie(request.headers.get("Cookie") ?? "", "session_id");
    if (!sessionId) {
      return Response.redirect(env.AUTH.getLoginUrl(request.url), 302);
    }
    const result = await env.AUTH.validateSession(sessionId);
    if (!result.valid) {
      return Response.redirect(env.AUTH.getLoginUrl(request.url), 302);
    }
    // ...handle authenticated request with result.session
  },
};
```

### Exchange mode (Pages previews, localhost, off-domain consumers)

The auth worker redirects to the consumer with `?__ssso_auth_code=<code>`. The consumer trades it for a session ID and sets its own cookie. This handler is safe to include on same-domain consumers too — the code param simply never shows up there.

```ts
export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    // Step 1: if we landed here with an exchange code, trade it and set our own cookie.
    const code = url.searchParams.get("__ssso_auth_code");
    if (code) {
      const result = await env.AUTH.exchangeAuthCode(code);
      if (!result) return new Response("Invalid or expired auth code", { status: 400 });

      url.searchParams.delete("__ssso_auth_code");
      const isLocal = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
      const cookieParts = [
        `session_id=${result.sessionId}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        `Max-Age=${result.expiresInSeconds}`,
      ];
      if (!isLocal) cookieParts.push("Secure");
      return new Response(null, {
        status: 302,
        headers: { Location: url.toString(), "Set-Cookie": cookieParts.join("; ") },
      });
    }

    // Step 2: normal request — check the cookie.
    const sessionId = parseCookie(request.headers.get("Cookie") ?? "", "session_id");
    if (!sessionId) return Response.redirect(env.AUTH.getLoginUrl(url.toString()), 302);

    const result = await env.AUTH.validateSession(sessionId);
    if (!result.valid) return Response.redirect(env.AUTH.getLoginUrl(url.toString()), 302);

    // ...handle authenticated request
  },
};
```

The exchange code is **single-use** and expires after **60 seconds** — if the consumer doesn't redeem it quickly, it's gone.

## Logout

The auth worker can also handle logout via redirect, keeping the flow symmetric with login:

```ts
// In your consumer's fetch handler — e.g. a "/logout" route
return Response.redirect(env.AUTH.getLogoutUrl("/"), 302);
```

The auth worker reads the `session_id` cookie, deletes the session from KV, clears the cookie, and redirects back.

For programmatic revocation (no browser redirect), use `deleteSession(sessionId)` directly.

## RPC reference

```ts
validateSession(sessionId: string, requiredGroups?: string[]): Promise<SessionValidationResult>;
deleteSession(sessionId: string): Promise<void>;
getLoginUrl(redirect?: string): string;
getLogoutUrl(redirect?: string): string;
exchangeAuthCode(code: string): Promise<{ sessionId: string; expiresInSeconds: number } | null>;
```

- `validateSession` — `requiredGroups` is OR logic; user needs to be in at least one.
- `getLoginUrl` — `redirect` must be on the allowlist (see below), otherwise it falls back to the auth homepage. Cookie vs. exchange mode is auto-detected from the redirect URL.
- `getLogoutUrl` — redirects the browser to the auth worker, which clears the session cookie and deletes the KV entry.
- `exchangeAuthCode` — returns `null` if the code is unknown, already used, or expired.

## Redirect allowlist

`getLoginUrl` only honors redirects that match one of:

- The deployment's cookie scope — derived from `AUTH_ORIGIN` by stripping the first DNS label (`auth.example.com` → `.example.com`, so all `*.example.com` consumers work)
- `localhost`, `127.0.0.1`, `[::1]`
- `EXTRA_REDIRECT_SUFFIXES` env var — comma-separated, e.g. `.foo.pages.dev,.bar.example.com`

Editing the env var in the Cloudflare dashboard takes effect on the next request — no code deploy needed. For one-off Pages previews that don't have a custom domain yet, add their suffix here.

## Environment variables

| Var                       | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `AUTH_ORIGIN`             | Public origin of the auth worker (base URL for `/login`)       |
| `BASE_URL`                | Synology SSO base URL                                          |
| `CLIENT_ID`               | Synology OAuth client ID                                       |
| `CLIENT_PASSWORD`         | Synology OAuth client secret (secret, not in `wrangler.jsonc`) |
| `EXTRA_REDIRECT_SUFFIXES` | Runtime-added redirect allowlist suffixes (comma-separated)    |

## Commands

- `bun dev` — start local dev server
- `bun run types` — regenerate `worker-configuration.d.ts` after changing `wrangler.jsonc`

## Architecture

- `contracts.d.ts` — single source of truth for public RPC types. Consumers import from here.
- `src/index.ts` — HTTP routes + `AuthService` RPC class
- `src/session.ts` — session / OAuth-state / exchange-code storage (all KV-backed)
- `src/synology.ts` — Synology SSO client

When changing the RPC surface, update `contracts.d.ts` to match before pushing.

## License

MIT
