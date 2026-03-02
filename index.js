import path from "node:path";
import { minimatch } from "minimatch";

// Default protected files — always blocked for read/write/edit in group sessions
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

/**
 * Collect all agent workspace directories from config.
 */
function collectWorkspaceRoots(config) {
  const roots = new Set();
  const defaultWorkspace =
    config?.agents?.defaults?.workspace ||
    path.join(process.env.HOME || "/", ".openclaw/workspace");
  roots.add(path.resolve(defaultWorkspace));

  const agents = config?.agents?.list;
  if (Array.isArray(agents)) {
    for (const agent of agents) {
      if (agent?.workspace) {
        roots.add(path.resolve(agent.workspace));
      }
      // Also check agentDir — some agents store identity files there
      if (agent?.agentDir) {
        roots.add(path.resolve(agent.agentDir));
      }
    }
  }
  return [...roots];
}

/**
 * Check if a session should be protected (non-main session).
 *
 * Only the main session (direct chat with owner via primary interface)
 * is trusted. ALL external channel sessions are protected, whether
 * DM or group — because any external message could be prompt injection.
 *
 * Session key formats:
 *   - Main:     agent:main:main  (trusted, owner direct chat)
 *   - External: agent:main:dmwork:direct:<id>  (protected)
 *   - Group:    agent:main:<channel>:group:<id> (protected)
 *   - Channel:  agent:main:<channel>:channel:<id> (protected)
 *   - Thread:   ...::thread:<id>  (inherits parent context)
 */
function isProtectedSession(sessionKey) {
  if (!sessionKey || typeof sessionKey !== "string") return true; // default: protect
  const base = sessionKey.replace(/::thread:[^:]+$/, "");
  // Only main sessions are trusted
  return !base.endsWith(":main");
}

/**
 * Resolve the file path from tool params.
 * Tools use different param names: path, file_path, filePath
 */
function resolveFilePath(params) {
  return (
    params?.file_path || params?.filePath || params?.path || params?.file || null
  );
}

/**
 * Check if a resolved absolute path falls within any protected pattern
 * relative to any of the workspace roots.
 */
function isProtectedFile(absolutePath, workspaceRoots, patterns) {
  if (!absolutePath) return false;
  const resolved = path.resolve(absolutePath);
  for (const root of workspaceRoots) {
    const relative = path.relative(root, resolved);
    // Skip if path escapes this workspace
    if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
    if (patterns.some((pattern) => minimatch(relative, pattern, { dot: true }))) {
      return true;
    }
  }
  return false;
}

/**
 * Resolve the absolute path of a file, trying each workspace root.
 * Returns the first workspace root that makes sense for this path.
 */
function resolveAbsoluteWithRoots(filePath, workspaceRoots) {
  if (!filePath) return { absolutePath: null, root: null };
  // If already absolute, use as-is
  if (path.isAbsolute(filePath)) {
    const resolved = path.resolve(filePath);
    // Find which workspace root it belongs to
    for (const root of workspaceRoots) {
      const relative = path.relative(root, resolved);
      if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
        return { absolutePath: resolved, root };
      }
    }
    return { absolutePath: resolved, root: workspaceRoots[0] };
  }
  // Relative path — resolve against first (default) workspace
  return {
    absolutePath: path.resolve(workspaceRoots[0], filePath),
    root: workspaceRoots[0],
  };
}

/**
 * Check if a path is inside (or equal to) a directory.
 */
function isPathInside(filePath, dir) {
  const resolved = path.resolve(filePath);
  const resolvedDir = path.resolve(dir);
  return resolved === resolvedDir || resolved.startsWith(resolvedDir + path.sep);
}

/**
 * Redirect a write/edit path to the allowed base directory.
 * Preserves the relative structure from the workspace root.
 */
function redirectPath(absolutePath, workspaceRoot, allowedBaseDir) {
  const resolved = path.resolve(absolutePath);
  // If already inside allowedBaseDir, no redirect needed
  if (isPathInside(resolved, allowedBaseDir)) return null;
  // Try to keep relative structure from workspace root
  const relative = path.relative(workspaceRoot, resolved);
  if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
    return path.join(allowedBaseDir, relative);
  }
  // Outside workspace: just use the basename
  return path.join(allowedBaseDir, path.basename(resolved));
}

/**
 * Rewrite params to use the redirected path.
 */
function rewriteParams(params, newPath) {
  const updated = { ...params };
  if (params?.file_path != null) updated.file_path = newPath;
  if (params?.filePath != null) updated.filePath = newPath;
  if (params?.path != null) updated.path = newPath;
  if (params?.file != null) updated.file = newPath;
  return updated;
}

// FS tools that we intercept
const READ_TOOLS = new Set(["read"]);
const WRITE_TOOLS = new Set(["write", "edit"]);

export function register(api) {
  const pluginConfig = api.pluginConfig || {};
  const workspaceRoots = collectWorkspaceRoots(api.config);
  const allowedBaseDir =
    pluginConfig.allowedBaseDir ||
    path.join(path.dirname(workspaceRoots[0]), "workspace_guard/sandbox");
  const protectedFiles = Array.isArray(pluginConfig.protectedFiles)
    ? pluginConfig.protectedFiles
    : DEFAULT_PROTECTED_FILES;

  api.logger.info?.(
    `workspace-guard active: protecting ${protectedFiles.length} patterns across ${workspaceRoots.length} workspaces, ` +
      `group writes → ${allowedBaseDir}`,
  );
  for (const root of workspaceRoots) {
    api.logger.info?.(`  workspace: ${root}`);
  }

  api.on("before_tool_call", (event, ctx) => {
    const toolName = (event.toolName || "").toLowerCase();

    // Only intercept fs tools
    if (!READ_TOOLS.has(toolName) && !WRITE_TOOLS.has(toolName) && toolName !== "apply_patch") {
      return;
    }

    // Only enforce in group/channel sessions
    if (!isProtectedSession(ctx.sessionKey)) return;

    const filePath = resolveFilePath(event.params);
    const { absolutePath, root } = resolveAbsoluteWithRoots(filePath, workspaceRoots);

    // --- READ tools ---
    if (READ_TOOLS.has(toolName)) {
      if (!absolutePath) return;
      if (isProtectedFile(absolutePath, workspaceRoots, protectedFiles)) {
        const displayPath = root
          ? path.relative(root, absolutePath)
          : path.basename(absolutePath);
        api.logger.warn?.(
          `[workspace-guard] BLOCKED read of protected file: ${displayPath} (session: ${ctx.sessionKey})`,
        );
        return {
          block: true,
          blockReason: `🛡️ Protected file — cannot read "${displayPath}" in group chat context.`,
        };
      }
      return;
    }

    // --- WRITE/EDIT tools ---
    if (WRITE_TOOLS.has(toolName)) {
      if (!absolutePath) return;

      // Always block writes to protected files
      if (isProtectedFile(absolutePath, workspaceRoots, protectedFiles)) {
        const displayPath = root
          ? path.relative(root, absolutePath)
          : path.basename(absolutePath);
        api.logger.warn?.(
          `[workspace-guard] BLOCKED write to protected file: ${displayPath} (session: ${ctx.sessionKey})`,
        );
        return {
          block: true,
          blockReason: `🛡️ Protected file — cannot modify "${displayPath}" in group chat context.`,
        };
      }

      // Redirect writes outside allowedBaseDir
      const effectiveRoot = root || workspaceRoots[0];
      const redirected = redirectPath(absolutePath, effectiveRoot, allowedBaseDir);
      if (redirected) {
        api.logger.info?.(
          `[workspace-guard] Redirecting write: ${filePath} → ${redirected} (session: ${ctx.sessionKey})`,
        );
        return { params: rewriteParams(event.params, redirected) };
      }

      return;
    }

    // --- APPLY_PATCH ---
    if (toolName === "apply_patch") {
      // apply_patch embeds file paths inside patch content — we cannot reliably
      // redirect paths without rewriting the patch format. Block entirely in
      // external sessions. The AI should use write/edit instead (which get
      // automatically redirected to the sandbox directory).
      api.logger.warn?.(
        `[workspace-guard] BLOCKED apply_patch in external session (session: ${ctx.sessionKey})`,
      );
      return {
        block: true,
        blockReason:
          "🛡️ apply_patch is not available in external sessions. Use write or edit instead — files will be saved to the sandbox directory.",
      };
    }
  });
}
