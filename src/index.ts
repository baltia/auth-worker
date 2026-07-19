import { generateCodeVerifier, generateState } from "arctic";
import { WorkerEntrypoint } from "cloudflare:workers";

import {
  consumeExchangeCode,
  consumeOAuthState,
  createSession,
  deleteSession as deleteSessionFromKV,
  generateExchangeCode,
  getSession,
  storeExchangeCode,
  storeOAuthState,
  validateSession as validateSessionData,
  type ExchangeResult,
  type SessionData,
  type SessionValidationResult,
} from "./session";
import type { Synology } from "arctic";
import { createSynologyClient, fetchUserInfo } from "./synology";
const lockIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ba1904" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-lock-icon lucide-lock"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
const lockOpenIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ba1904" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-lock-open-icon lucide-lock-open"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`;

// MARK: - RPC (Service Bindings)

export class AuthService extends WorkerEntrypoint<Env> {
  async validateSession(
    sessionId: string,
    requiredGroups?: string[],
  ): Promise<SessionValidationResult> {
    const session = await getSession(this.env.SESSIONS, sessionId);
    return validateSessionData(session, requiredGroups);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await deleteSessionFromKV(this.env.SESSIONS, sessionId);
  }

  async getLoginUrl(redirect?: string): Promise<string> {
    const url = new URL("/login", this.env.AUTH_ORIGIN);
    if (redirect) url.searchParams.set("redirect", redirect);
    return url.toString();
  }

  async getLogoutUrl(redirect?: string): Promise<string> {
    const url = new URL("/logout", this.env.AUTH_ORIGIN);
    if (redirect) url.searchParams.set("redirect", redirect);
    return url.toString();
  }

  async exchangeAuthCode(code: string): Promise<ExchangeResult | null> {
    return consumeExchangeCode(this.env.SESSIONS, code);
  }
}

// MARK: - HTTP (public OAuth flow)

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case "/":
        return handleStatus(request, env);
      case "/login":
        return handleLogin(url, env);
      case "/callback":
        return handleCallback(url, env);
      case "/logout":
        return handleLogout(request, env);
      case "/favicon.ico":
        return new Response(lockIcon, {
          headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" },
        });
      default:
        return new Response("Not found", { status: 404 });
    }
  },
};

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const EXCHANGE_CODE_PARAM = "__ssso_auth_code";

// Strip the first DNS label from AUTH_ORIGIN: auth.example.com → .example.com.
// Assumes the deployment lives at a subdomain and the target cookie scope is a single-label public suffix.
// Multi-label suffixes (foo.co.uk) or ad-hoc preview origins should go through EXTRA_REDIRECT_SUFFIXES.
function cookieDomainOf(env: Env): string {
  const host = new URL(env.AUTH_ORIGIN).hostname;
  const dot = host.indexOf(".");
  return dot > 0 ? host.slice(dot) : host;
}

function hostnameMatchesSuffix(hostname: string, suffix: string): boolean {
  return hostname === suffix.slice(1) || hostname.endsWith(suffix);
}

function isCookieReachable(redirectUrl: string, env: Env): boolean {
  if (redirectUrl.startsWith("/")) return true;
  try {
    return hostnameMatchesSuffix(new URL(redirectUrl).hostname, cookieDomainOf(env));
  } catch {
    return false;
  }
}

function parseExtraSuffixes(env: Env): string[] {
  return (env.EXTRA_REDIRECT_SUFFIXES ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function isAllowedRedirect(redirect: string, env: Env): boolean {
  if (redirect.startsWith("/")) return true;
  try {
    const { hostname } = new URL(redirect);
    if (LOCAL_HOSTS.has(hostname)) return true;
    const suffixes = [cookieDomainOf(env), ...parseExtraSuffixes(env)];
    return suffixes.some((suffix) => hostnameMatchesSuffix(hostname, suffix));
  } catch {
    return false;
  }
}

function sanitizeRedirect(redirect: string | null, defaultUrl: string, env: Env): string {
  if (!redirect) return defaultUrl;
  if (isAllowedRedirect(redirect, env)) return redirect;
  console.warn(`Blocked suspicious redirect: ${redirect}`);
  return defaultUrl;
}

async function handleStatus(request: Request, env: Env): Promise<Response> {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const sessionId = parseCookie(cookieHeader, "session_id");

  let session: SessionData | null = null;
  if (sessionId) {
    try {
      session = await getSession(env.SESSIONS, sessionId);
    } catch (e) {
      console.error("Failed to fetch session for status page", String(e));
    }
  }

  return new Response(statusPage(session), {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

async function handleLogin(url: URL, env: Env): Promise<Response> {
  const redirectUrl = sanitizeRedirect(
    url.searchParams.get("redirect"),
    env.AUTH_ORIGIN + "/",
    env,
  );

  const synology = createSynologyClient(env);
  const state = generateState();
  const codeVerifier = generateCodeVerifier();

  const authUrl = synology.createAuthorizationURL(state, codeVerifier, [
    "email",
    "groups",
    "openid",
  ]);

  try {
    await storeOAuthState(env.SESSIONS, state, codeVerifier, redirectUrl);
  } catch (e) {
    console.error("Failed to store OAuth state in KV", String(e));
    return new Response("Login failed: unable to initiate authentication. Please try again.", {
      status: 500,
    });
  }

  return Response.redirect(authUrl.toString(), 302);
}

async function handleCallback(url: URL, env: Env): Promise<Response> {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Missing code or state", { status: 400 });
  }

  // Warm the connection to the NAS in parallel with the KV state lookup so the
  // token exchange below doesn't pay TLS/handshake cost on a cold route.
  const warmup = fetch(env.BASE_URL, { method: "HEAD" }).catch(() => {});

  const oauthState = await consumeOAuthState(env.SESSIONS, state);
  if (!oauthState) {
    return new Response("Invalid or expired state", { status: 400 });
  }

  const synology = createSynologyClient(env);

  await warmup;

  let accessToken: string;
  try {
    accessToken = await exchangeAuthCodeWithRetry(synology, code, oauthState.codeVerifier);
  } catch (e) {
    console.error(
      "Token exchange failed after retry",
      String(e),
      "cause:",
      e instanceof Error ? e.cause : "N/A",
    );
    return new Response(tokenExchangeFailedPage(oauthState.redirectUrl), {
      status: 502,
      headers: { "Content-Type": "text/html;charset=UTF-8" },
    });
  }

  let userData;
  try {
    userData = await fetchUserInfo(env.BASE_URL, accessToken);
  } catch (e) {
    console.error(
      "Failed to fetch user info",
      String(e),
      "cause:",
      e instanceof Error ? e.cause : "N/A",
    );
    return new Response("Failed to fetch user info", { status: 500 });
  }

  let sessionResult;
  try {
    sessionResult = await createSession(env.SESSIONS, userData);
  } catch (e) {
    console.error("Failed to create session in KV", String(e));
    return new Response("Login failed: unable to create session. Please try again.", {
      status: 500,
    });
  }

  if (!isCookieReachable(oauthState.redirectUrl, env)) {
    const exchangeCode = generateExchangeCode();
    try {
      await storeExchangeCode(env.SESSIONS, exchangeCode, {
        sessionId: sessionResult.sessionId,
        expiresInSeconds: sessionResult.expiresInSeconds,
      });
    } catch (e) {
      console.error("Failed to store exchange code in KV", String(e));
      return new Response("Login failed: unable to issue exchange code. Please try again.", {
        status: 500,
      });
    }

    const target = new URL(oauthState.redirectUrl);
    target.searchParams.set(EXCHANGE_CODE_PARAM, exchangeCode);
    return Response.redirect(target.toString(), 302);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: oauthState.redirectUrl,
      "Set-Cookie": buildSessionCookie(
        url,
        sessionResult.sessionId,
        sessionResult.expiresInSeconds,
        env,
      ),
    },
  });
}

// Retry once on any error. A cold route to the NAS often fails the first request
// even after a warmup ping; the second usually succeeds on the now-open connection.
async function exchangeAuthCodeWithRetry(
  synology: Synology,
  code: string,
  codeVerifier: string,
): Promise<string> {
  try {
    const tokens = await synology.validateAuthorizationCode(code, codeVerifier);
    return tokens.accessToken();
  } catch (e) {
    console.warn(
      "Token exchange failed, retrying once",
      String(e),
      "cause:",
      e instanceof Error ? e.cause : "N/A",
    );
    const tokens = await synology.validateAuthorizationCode(code, codeVerifier);
    return tokens.accessToken();
  }
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectUrl = sanitizeRedirect(url.searchParams.get("redirect"), "/", env);

  const cookieHeader = request.headers.get("Cookie") ?? "";
  const sessionId = parseCookie(cookieHeader, "session_id");

  if (sessionId) {
    await deleteSessionFromKV(env.SESSIONS, sessionId);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectUrl,
      "Set-Cookie": buildSessionCookie(url, "", 0, env),
    },
  });
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Baltia design tokens — mirrors ../intern-new/DESIGN.md + layout.css.
// Closed triad: red (signal only — title block, links, focus), black (primary),
// silver (breath). Sharp corners, Nunito body, Noto Serif headings, warm neutrals.
const BALTIA_STYLES = `
@font-face{font-family:'Nunito Variable';font-style:normal;font-weight:200 1000;font-display:swap;src:url(/fonts/nunito-latin-wght-normal.woff2) format('woff2-variations')}
@font-face{font-family:'Noto Serif Variable';font-style:normal;font-weight:100 900;font-display:swap;src:url(/fonts/noto-serif-latin-wght-normal.woff2) format('woff2-variations')}
:root{
--background:#f5f5f5;--foreground:#0a0a0a;
--card:#faf8f7;--border:#e2dedc;--muted:#f0edec;--muted-foreground:#6e6862;
--primary:#171717;--primary-foreground:#f0edec;
--baltia-red:#ba1904;--link:#ba1904;
}
@media(prefers-color-scheme:dark){:root{
--background:#0a0a0a;--foreground:#f5f5f5;
--card:#171717;--border:rgba(255,255,255,.1);--muted:#262626;--muted-foreground:#aaa49e;
--primary:#f0edec;--primary-foreground:#171717;
--link:#dc4326;
}}
body{font-family:'Nunito Variable',system-ui,sans-serif;background:var(--background);color:var(--foreground);display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:1rem;box-sizing:border-box}
.card{background:var(--card);border:1px solid var(--border);padding:2rem;text-align:center;max-width:26rem;width:100%;box-sizing:border-box}
h1{font-family:'Noto Serif Variable',Georgia,serif;font-weight:600;font-size:1.5rem;line-height:1.2;display:inline-block;background:var(--baltia-red);color:#fff;border-radius:2px;padding:.75rem 1rem .5rem;margin:0 0 .75rem}
p{color:var(--muted-foreground);margin:.5rem 0;line-height:1.6}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
a.btn{display:inline-block;background:var(--primary);color:var(--primary-foreground);font-weight:600;font-size:.875rem;padding:.5rem 1.25rem;margin-top:1rem;border-radius:0}
a.btn:hover{opacity:.85;text-decoration:none}
pre{text-align:left;background:var(--muted);padding:1rem;overflow-x:auto;font-size:.8rem;line-height:1.5}
`;

function renderPage(title: string, icon: string, content: string): string {
  const favicon = `data:image/svg+xml,${encodeURIComponent(icon)}`;
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${title}</title>
<link rel="icon" type="image/svg+xml" href="${favicon}">
<style>${BALTIA_STYLES}</style>
</head><body><main class="card">${content}</main></body></html>`;
}

function statusPage(session: SessionData | null): string {
  if (session) {
    const { accessToken: _, ...safeSession } = session;
    return renderPage(
      "ssso-auth",
      lockIcon,
      `<h1>Logged in</h1>
       <p>Signed in as <strong>${escapeHtml(session.userName)}</strong></p>
       <pre>${escapeHtml(JSON.stringify(safeSession, null, 2))}</pre>
       <a class="btn" href="/logout">Log out</a>`,
    );
  }
  return renderPage(
    "ssso-auth",
    lockOpenIcon,
    `<h1>Not logged in</h1>
     <p>Sign in with your Baltia account.</p>
     <a class="btn" href="/login">Log in</a>`,
  );
}

function tokenExchangeFailedPage(redirectUrl: string): string {
  const loginUrl = `/login?redirect=${encodeURIComponent(redirectUrl)}`;
  return renderPage(
    "Sign-in failed",
    lockOpenIcon,
    `<h1>Sign-in failed</h1>
     <p>We couldn't reach the authentication server. Please try again.</p>
     <a class="btn" href="${escapeHtml(loginUrl)}">Log in again</a>`,
  );
}

// Prod: Domain=<cookieDomainOf(env)> shares the cookie across subdomains. Local dev: host-only, no Secure.
function buildSessionCookie(requestUrl: URL, sessionId: string, maxAge: number, env: Env): string {
  const isLocal = LOCAL_HOSTS.has(requestUrl.hostname);
  const parts = [
    `session_id=${sessionId}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ];
  if (!isLocal) parts.push(`Domain=${cookieDomainOf(env)}`, "Secure");
  return parts.join("; ");
}

function parseCookie(cookieHeader: string, name: string): string | null {
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}
