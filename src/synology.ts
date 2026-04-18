import { Synology } from "arctic";
import type { SessionData } from "./session";

export function createSynologyClient(env: Env): Synology {
  return new Synology(
    env.BASE_URL,
    env.CLIENT_ID,
    env.CLIENT_PASSWORD,
    env.AUTH_ORIGIN + "/callback",
  );
}

// Calls the Synology SSO UserInfo endpoint (proprietary to DSM's SSO Server package)
export async function fetchUserInfo(
  baseUrl: string,
  accessToken: string,
): Promise<Omit<SessionData, "createdAt" | "expiresAt">> {
  const endpoint = new URL("webman/sso/SSOUserInfo.cgi", baseUrl);
  const response = await fetch(endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch user info: ${response.status}`);
  }

  let info: Record<string, unknown>;
  try {
    info = (await response.json()) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`Synology SSO returned non-JSON response (status ${response.status})`, {
      cause: e,
    });
  }

  if (
    typeof info.sub !== "string" ||
    !info.sub ||
    typeof info.username !== "string" ||
    !info.username
  ) {
    throw new Error("User info missing required fields (sub, username)");
  }

  return {
    userId: info.sub,
    userName: info.username,
    accessToken,
    email: typeof info.email === "string" ? info.email : undefined,
    groups: Array.isArray(info.groups) ? (info.groups as string[]) : [],
  };
}
