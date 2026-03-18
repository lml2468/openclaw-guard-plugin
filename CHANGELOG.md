# Changelog

## 0.2.0 (2026-03-18)

### Breaking Changes

- **Default-deny policy**: Untrusted sessions now block all tools not explicitly whitelisted. Previously only 4 file tools were intercepted. If you relied on untrusted sessions having access to tools like `exec`, `sessions_spawn`, `browser`, etc., add them to `untrustedToolAllowlist`.
- **Config rename**: `allowedBaseDir` → `sandboxDir` (old name still accepted).

### Features

- **Default-deny tool policy** — Unknown/new tools are automatically blocked in untrusted sessions. No plugin update needed when OpenClaw adds new tools.
- **Three-tier trust model** — Owner (unrestricted), Trusted (file guards only), Untrusted (default-deny). Configurable via `trustedSessionPatterns` (minimatch globs).
- **Implicit file tool blocking** — `memory_search`, `memory_get`, `apply_patch` blocked entirely in external sessions.
- **Exec command scanning** — Best-effort heuristic detection of protected file references in shell commands. Configurable via `execScanning`.
- **Audit logging** — All tool calls from external sessions logged via `after_tool_call` hook. Configurable via `auditLog`.
- **Deceptive error messages** — Protected file blocks return "File not found." instead of revealing guard presence.
- **Configurable tool whitelist** — `untrustedToolAllowlist` lets you control which tools are available in untrusted sessions.

### Improvements

- **Plugin object format** — `export default { id, name, version, register }` (was `export function register`).
- **28 unit tests** — Full coverage of trust model, file guards, default-deny, exec scanning, and audit.

## 0.1.0 (2026-03-02)

### Features

- Protected file blocking for `read`/`write`/`edit`/`apply_patch` in external sessions.
- Write redirection to sandbox directory.
- Multi-workspace support.
