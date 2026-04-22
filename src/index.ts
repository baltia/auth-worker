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
import { createSynologyClient, fetchUserInfo } from "./synology";
const lockIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-lock-icon lucide-lock"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
const lockOpenIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-lock-open-icon lucide-lock-open"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`;

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

  getLoginUrl(redirect?: string): string {
    const url = new URL("/login", this.env.AUTH_ORIGIN);
    if (redirect) url.searchParams.set("redirect", redirect);
    return url.toString();
  }

  getLogoutUrl(redirect?: string): string {
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

  const oauthState = await consumeOAuthState(env.SESSIONS, state);
  if (!oauthState) {
    return new Response("Invalid or expired state", { status: 400 });
  }

  const synology = createSynologyClient(env);

  let accessToken: string;
  try {
    const tokens = await synology.validateAuthorizationCode(code, oauthState.codeVerifier);
    accessToken = tokens.accessToken();
  } catch (e) {
    console.error(
      "Token exchange failed",
      String(e),
      "cause:",
      e instanceof Error ? e.cause : "N/A",
    );
    return new Response("Token exchange failed", { status: 400 });
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

function statusPage(session: SessionData | null): string {
  const icon = session ? lockIcon : lockOpenIcon;
  const favicon = `data:image/svg+xml,${encodeURIComponent(icon)}`;
  let content: string;

  if (session) {
    const { accessToken: _, ...safeSession } = session;
    content = `<h1>Logged in</h1>
       <p>Signed in as <strong>${escapeHtml(session.userName)}</strong></p>
       <pre>${escapeHtml(JSON.stringify(safeSession, null, 2))}</pre>
       <a href="/logout">Log out</a>`;
  } else {
    content = `<h1>Not logged in</h1><p><a href="/login">Log in</a></p>`;
  }

  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ssso-auth</title>
<link rel="icon" type="image/svg+xml" href="${favicon}">
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
.card{background:#fff;border-radius:8px;padding:2rem;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;max-width:400px}
h1{margin:0 0 .5rem;font-size:1.5rem}p{color:#666;margin:.5rem 0}a{color:#2563eb}
pre{text-align:left;background:#f0f0f0;padding:1rem;border-radius:4px;overflow-x:auto;font-size:.85rem}</style>
</head><body><div class="card">${content}</div></body></html>`;
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
