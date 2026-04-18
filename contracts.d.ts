import { WorkerEntrypoint } from "cloudflare:workers";

export interface SessionData {
  userId: string;
  userName: string;
  accessToken: string;
  email?: string;
  groups: string[];
  createdAt: number;
  expiresAt: number;
}

export type SessionValidationResult =
  | { valid: false; session: null }
  | { valid: true; session: SessionData };

export interface ExchangeResult {
  sessionId: string;
  expiresInSeconds: number;
}

export declare class AuthService extends WorkerEntrypoint {
  validateSession(sessionId: string, requiredGroups?: string[]): Promise<SessionValidationResult>;
  deleteSession(sessionId: string): Promise<void>;
  getLoginUrl(redirect?: string): string;
  /** Returns null if the code is unknown, consumed, or expired. */
  exchangeAuthCode(code: string): Promise<ExchangeResult | null>;
}
