import path from "node:path";
import { minimatch } from "minimatch";

// =============================================================================
// Defaults
// =============================================================================

const DEFAULT_PROTECTED_FILES = [
  "SOUL.md",
  "AGENTS.md",
  "USER.md",
  "IDENTITY.md",
  "MEMORY.md",
  "TOOLS.md",
  "HEARTBEAT.md",
  "memory/*.md",
];

const DEFAULT_TRUSTED_PATTERNS = ["*:main"];

// Tools unconditionally allowed in untrusted sessions (no file/workspace access)
const DEFAULT_UNTRUSTED_ALLOWED_TOOLS = [
  "web_search",
  "web_fetch",
  "tts",
  "message",
];

// FS tools needing parameter-level guards
const FILE_READ_TOOLS = new Set(["read"]);
const FILE_WRITE_TOOLS = new Set(["write", "edit"]);

// Tools that implicitly access workspace files without inspectable path params
const IMPLICIT_FILE_TOOLS = new Set([
  "memory_search",
  "memory_get",
  "apply_patch",
]);

// Protected file base names for exec command scanning
const DEFAULT_PROTECTED_LITERALS = [
  "SOUL.md",
  "AGENTS.md",
  "USER.md",
  "IDENTITY.md",
  "MEMORY.md",
  "TOOLS.md",
  "HEARTBEAT.md",
];

// Best-effort heuristic patterns for exec commands targeting .md files.
// NOT a security boundary — determined attackers can bypass these trivially.
const SUSPICIOUS_EXEC_PATTERNS = [
  /\b(?:cat|head|tail|less|more|bat)\b.*\.md\b/i,
  /\b(?:sed|awk)\b.*\.md\b/i,
  /\btee\b.*\.md\b/i,
  /\b(?:cp|mv|rm)\b.*\.md\b/i,
  />\s*\S*\.md\b/,
];

// =============================================================================
// Trust Model
// =============================================================================

/**
 * Determine trust level of a session.
 *
 * - "owner":     main session — unrestricted
 * - "trusted":   explicitly trusted patterns — file guards only, other tools allowed
 * - "untrusted": everything else — default-deny, whitelist only
 *
 * Thread suffixes (::thread:<id>) are stripped so threads inherit parent trust.
 */
function getTrustLevel(sessionKey, trustedPatterns) {
  if (!sessionKey || typeof sessionKey !== "string") return "untrusted";
  const base = sessionKey.replace(/::thread:[^:]+$/, "");

  for (const pattern of trustedPatterns) {
    if (minimatch(base, pattern, { dot: true })) {
      // Default *:main → owner; other explicit patterns → trusted
      if (pattern === "*:main" && base.endsWith(":main")) return "owner";
      return "trusted";
    }
  }
  return "untrusted";
}

// =============================================================================
// File Path Utilities
// =============================================================================

function resolveFilePath(params) {
  return params?.file_path || params?.filePath || params?.path || params?.file || null;
}

function collectWorkspaceRoots(config) {
  const roots = new Set();
  const defaultWorkspace =
    config?.agents?.defaults?.workspace ||
    path.join(process.env.HOME || "/", ".openclaw/workspace");
  roots.add(path.resolve(defaultWorkspace));

  const agents = config?.agents?.list;
  if (Array.isArray(agents)) {
    for (const agent of agents) {
      if (agent?.workspace) roots.add(path.resolve(agent.workspace));
      if (agent?.agentDir) roots.add(path.resolve(agent.agentDir));
    }
  }
  return [...roots];
}

function isProtectedFile(absolutePath, workspaceRoots, patterns) {
  if (!absolutePath) return false;
  const resolved = path.resolve(absolutePath);
  for (const root of workspaceRoots) {
    const relative = path.relative(root, resolved);
    if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
    if (patterns.some((p) => minimatch(relative, p, { dot: true }))) return true;
  }
  return false;
}

function resolveAbsolute(filePath, workspaceRoots) {
  if (!filePath) return { absolutePath: null, root: null };
  if (path.isAbsolute(filePath)) {
    const resolved = path.resolve(filePath);
    for (const root of workspaceRoots) {
      const rel = path.relative(root, resolved);
      if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
        return { absolutePath: resolved, root };
      }
    }
    return { absolutePath: resolved, root: workspaceRoots[0] };
  }
  return {
    absolutePath: path.resolve(workspaceRoots[0], filePath),
    root: workspaceRoots[0],
  };
}

function isPathInside(filePath, dir) {
  const resolved = path.resolve(filePath);
  const resolvedDir = path.resolve(dir);
  return resolved === resolvedDir || resolved.startsWith(resolvedDir + path.sep);
}

function redirectPath(absolutePath, workspaceRoot, sandboxDir) {
  const resolved = path.resolve(absolutePath);
  if (isPathInside(resolved, sandboxDir)) return null;
  const relative = path.relative(workspaceRoot, resolved);
  if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
    return path.join(sandboxDir, relative);
  }
  return path.join(sandboxDir, path.basename(resolved));
}

function rewriteParams(params, newPath) {
  const updated = { ...params };
  if (params?.file_path != null) updated.file_path = newPath;
  if (params?.filePath != null) updated.filePath = newPath;
  if (params?.path != null) updated.path = newPath;
  if (params?.file != null) updated.file = newPath;
  return updated;
}

// =============================================================================
// Guard Functions
// =============================================================================

function checkFileRead(params, workspaceRoots, protectedPatterns) {
  const filePath = resolveFilePath(params);
  const { absolutePath } = resolveAbsolute(filePath, workspaceRoots);
  if (!absolutePath) return null;
  if (isProtectedFile(absolutePath, workspaceRoots, protectedPatterns)) {
    return { block: true, blockReason: "File not found." };
  }
  return null;
}

function checkFileWrite(params, workspaceRoots, protectedPatterns, sandboxDir) {
  const filePath = resolveFilePath(params);
  const { absolutePath, root } = resolveAbsolute(filePath, workspaceRoots);
  if (!absolutePath) return null;
  if (isProtectedFile(absolutePath, workspaceRoots, protectedPatterns)) {
    return { block: true, blockReason: "File not found." };
  }
  const effectiveRoot = root || workspaceRoots[0];
  const redirected = redirectPath(absolutePath, effectiveRoot, sandboxDir);
  if (redirected) {
    return { params: rewriteParams(params, redirected) };
  }
  return null;
}

function checkExec(params, protectedLiterals, workspaceRoots, sandboxDir) {
  const command = params?.command || "";
  if (command) {
    for (const literal of protectedLiterals) {
      if (command.includes(literal)) {
        return { block: true, blockReason: "Command references protected file." };
      }
    }
    for (const pattern of SUSPICIOUS_EXEC_PATTERNS) {
      if (pattern.test(command)) {
        return { block: true, blockReason: "Command matches suspicious pattern." };
      }
    }
  }
  const workdir = params?.workdir;
  if (workdir) {
    for (const root of workspaceRoots) {
      if (isPathInside(path.resolve(workdir), root)) {
        return { params: { ...params, workdir: sandboxDir } };
      }
    }
  }
  return null;
}

// =============================================================================
// Audit Logging
// =============================================================================

function logGuardAction(logger, action, toolName, sessionKey, reason) {
  const level = action === "blocked" ? "warn" : "info";
  logger[level]?.(
    `[workspace-guard] ${action} | tool=${toolName} | session=${sessionKey} | reason=${reason || "n/a"}`,
  );
}

// =============================================================================
// Plugin Definition
// =============================================================================

export default {
  id: "workspace-guard",
  name: "OpenClaw Guard",
  description:
    "Protect workspace files from prompt injection. Default-deny tool policy for untrusted sessions with file path guards, exec scanning, and audit logging.",
  version: "0.2.0",

  register(api) {
    const pluginConfig = api.pluginConfig || {};
    const workspaceRoots = collectWorkspaceRoots(api.config);

    // --- Config with defaults ---
    const sandboxDir =
      pluginConfig.sandboxDir ||
      pluginConfig.allowedBaseDir || // backward compat
      path.join(path.dirname(workspaceRoots[0]), "workspace_guard/sandbox");

    const protectedPatterns = Array.isArray(pluginConfig.protectedFiles)
      ? pluginConfig.protectedFiles
      : DEFAULT_PROTECTED_FILES;

    const trustedPatterns = Array.isArray(pluginConfig.trustedSessionPatterns)
      ? pluginConfig.trustedSessionPatterns
      : DEFAULT_TRUSTED_PATTERNS;

    const untrustedAllowedTools = new Set(
      Array.isArray(pluginConfig.untrustedToolAllowlist)
        ? pluginConfig.untrustedToolAllowlist
        : DEFAULT_UNTRUSTED_ALLOWED_TOOLS,
    );

    const execScanning = pluginConfig.execScanning !== false;
    const auditLog = pluginConfig.auditLog !== false;

    const protectedLiterals = Array.isArray(pluginConfig.protectedLiterals)
      ? pluginConfig.protectedLiterals
      : DEFAULT_PROTECTED_LITERALS;

    // --- Startup log ---
    api.logger.info?.(
      `[workspace-guard] v0.2.0 | ` +
        `${protectedPatterns.length} protected patterns | ` +
        `${workspaceRoots.length} workspaces | ` +
        `${untrustedAllowedTools.size} allowed tools (untrusted) | ` +
        `sandbox: ${sandboxDir}`,
    );

    // --- Main guard hook ---
    api.on(
      "before_tool_call",
      (event, ctx) => {
        const toolName = (event.toolName || "").toLowerCase();
        const trustLevel = getTrustLevel(ctx.sessionKey, trustedPatterns);

        // Owner: unrestricted
        if (trustLevel === "owner") return;

        // =====================================================================
        // UNTRUSTED sessions: default-deny with whitelist
        // =====================================================================
        if (trustLevel === "untrusted") {
          // 1. Unconditionally safe tools
          if (untrustedAllowedTools.has(toolName)) return;

          // 2. File read: allow with path guard
          if (FILE_READ_TOOLS.has(toolName)) {
            const result = checkFileRead(event.params, workspaceRoots, protectedPatterns);
            if (result) {
              logGuardAction(api.logger, "blocked", toolName, ctx.sessionKey, result.blockReason);
              return result;
            }
            return; // non-protected read is OK
          }

          // 3. File write/edit: allow with path guard + redirect
          if (FILE_WRITE_TOOLS.has(toolName)) {
            const result = checkFileWrite(event.params, workspaceRoots, protectedPatterns, sandboxDir);
            if (result) {
              logGuardAction(
                api.logger,
                result.block ? "blocked" : "redirected",
                toolName,
                ctx.sessionKey,
                result.blockReason || "sandbox redirect",
              );
              return result;
            }
            return;
          }

          // 4. Exec: allow with command scanning
          if (toolName === "exec" && execScanning) {
            const result = checkExec(event.params, protectedLiterals, workspaceRoots, sandboxDir);
            if (result) {
              logGuardAction(
                api.logger,
                result.block ? "blocked" : "redirected",
                toolName,
                ctx.sessionKey,
                result.blockReason || "workdir redirect",
              );
              return result;
            }
            return;
          }

          // 5. Implicit file tools: block
          if (IMPLICIT_FILE_TOOLS.has(toolName)) {
            logGuardAction(api.logger, "blocked", toolName, ctx.sessionKey, "implicit file tool");
            return { block: true, blockReason: "Not available in this context." };
          }

          // 6. DEFAULT DENY — everything not whitelisted is blocked
          logGuardAction(api.logger, "blocked", toolName, ctx.sessionKey, "not in allowlist");
          return { block: true, blockReason: "Not available in this context." };
        }

        // =====================================================================
        // TRUSTED sessions: file guards only, all tools allowed
        // =====================================================================
        if (trustLevel === "trusted") {
          if (FILE_READ_TOOLS.has(toolName)) {
            const result = checkFileRead(event.params, workspaceRoots, protectedPatterns);
            if (result) {
              logGuardAction(api.logger, "blocked", toolName, ctx.sessionKey, result.blockReason);
              return result;
            }
            return;
          }

          if (FILE_WRITE_TOOLS.has(toolName)) {
            const result = checkFileWrite(event.params, workspaceRoots, protectedPatterns, sandboxDir);
            if (result) {
              logGuardAction(
                api.logger,
                result.block ? "blocked" : "redirected",
                toolName,
                ctx.sessionKey,
                result.blockReason || "sandbox redirect",
              );
              return result;
            }
            return;
          }

          if (toolName === "exec" && execScanning) {
            const result = checkExec(event.params, protectedLiterals, workspaceRoots, sandboxDir);
            if (result) {
              logGuardAction(
                api.logger,
                result.block ? "blocked" : "redirected",
                toolName,
                ctx.sessionKey,
                result.blockReason || "workdir redirect",
              );
              return result;
            }
            return;
          }

          if (IMPLICIT_FILE_TOOLS.has(toolName)) {
            logGuardAction(api.logger, "blocked", toolName, ctx.sessionKey, "implicit file tool");
            return { block: true, blockReason: "Not available in this context." };
          }

          // Trusted: all other tools allowed
          return;
        }
      },
      { priority: 100 },
    );

    // --- Audit hook ---
    if (auditLog) {
      api.on("after_tool_call", (event, ctx) => {
        const trustLevel = getTrustLevel(ctx.sessionKey, trustedPatterns);
        if (trustLevel === "owner") return;
        api.logger.info?.(
          `[guard-audit] ${trustLevel} | ${ctx.sessionKey} | ${event.toolName} | ` +
            `${event.error ? "error" : "ok"} | ${event.durationMs ?? "?"}ms`,
        );
      });
    }
  },
};
