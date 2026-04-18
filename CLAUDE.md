# CLAUDE.md - ssso-auth

## Commands

- `bun dev` - Start development server
- `bun run types` - Regenerate Cloudflare Worker types (worker-configuration.d.ts)

## Tech Stack

- Cloudflare Workers (runtime)
- TypeScript with strict mode
- KV for session storage
- arctic for OAuth/PKCE
- Synology SSO as identity provider

## Architecture

- `contracts.d.ts` — Single source of truth for public RPC types (DTOs + AuthService declaration). Worker source imports from here.
- `src/index.ts` — Worker entrypoint: HTTP routes (OAuth flow) and `AuthService` RPC class
- `src/session.ts` — Session CRUD, validation, OAuth state management via KV
- `src/synology.ts` — Synology SSO client and user info fetching

## Contracts

Consumer workers consume `AuthService` via Cloudflare Service Bindings.
The public contract lives in `contracts.d.ts` — a plain declaration file, no build step.

**Before pushing changes that modify the public RPC surface (AuthService methods or DTO types), update `contracts.d.ts` to match.**

Consumer repos install this package via git and import types:

```ts
import type { AuthService, SessionData } from "ssso-auth";
```
