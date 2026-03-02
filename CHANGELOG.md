# Changelog

## 0.1.0 (2026-03-02)

### Features

- **Protected files**: Block read/write/edit/apply_patch of critical workspace files (SOUL.md, AGENTS.md, USER.md, IDENTITY.md, MEMORY.md, TOOLS.md, HEARTBEAT.md, memory/*.md) in external sessions.
- **Write redirection**: Automatically redirect file writes in external sessions to a configurable sandboxed directory, preserving relative path structure.
- **Multi-workspace support**: Protect files across all configured agent workspaces (default + per-agent workspaces and agent directories).
- **apply_patch guard**: Parse unified diff headers to detect and block patches targeting protected files.
- **Session detection**: Only the main session (direct owner chat) is trusted. All external channel sessions (DM, group, channel, thread) are protected by default.
- **Configurable**: Custom protected file patterns (glob via minimatch) and custom sandbox directory via plugin config.
