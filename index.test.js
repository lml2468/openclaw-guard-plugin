import { describe, it, expect, vi, beforeEach } from "vitest";
import path from "node:path";

// We test by importing the plugin and calling register() with a mock API
let plugin;

beforeEach(async () => {
  // Fresh import each time
  plugin = (await import("./index.js")).default;
});

function createMockApi(overrides = {}) {
  const hooks = {};
  const api = {
    config: {
      agents: {
        defaults: { workspace: "/home/user/.openclaw/workspace" },
      },
    },
    pluginConfig: overrides.pluginConfig || {},
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
    on: vi.fn((hookName, handler, opts) => {
      if (!hooks[hookName]) hooks[hookName] = [];
      hooks[hookName].push({ handler, opts });
    }),
    registerHook: vi.fn((hookName, handler, opts) => {
      if (!hooks[hookName]) hooks[hookName] = [];
      hooks[hookName].push({ handler, opts });
    }),
    _hooks: hooks,
  };
  return api;
}

function getBeforeToolCallHandler(api) {
  const entries = api._hooks["before_tool_call"];
  if (!entries || entries.length === 0) throw new Error("No before_tool_call hook registered");
  return entries[0].handler;
}

function callHook(handler, toolName, params, sessionKey) {
  return handler(
    { toolName, params: params || {} },
    { sessionKey, agentId: "main" },
  );
}

// =============================================================================
// Trust Model
// =============================================================================

describe("Trust Model", () => {
  it("owner session (main) is unrestricted", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    // Owner can read protected files
    const result = callHook(handler, "read", { path: "SOUL.md" }, "agent:main:main");
    expect(result).toBeUndefined();
  });

  it("untrusted session blocks unknown tools (default-deny)", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "some_new_tool", {}, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });

  it("untrusted session allows whitelisted tools", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    expect(callHook(handler, "web_search", {}, "agent:main:discord:channel:123")).toBeUndefined();
    expect(callHook(handler, "web_fetch", {}, "agent:main:discord:channel:123")).toBeUndefined();
    expect(callHook(handler, "tts", {}, "agent:main:discord:channel:123")).toBeUndefined();
    expect(callHook(handler, "message", {}, "agent:main:discord:channel:123")).toBeUndefined();
  });

  it("thread inherits parent trust level", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    // Main session thread → owner
    const result = callHook(handler, "read", { path: "SOUL.md" }, "agent:main:main::thread:abc");
    expect(result).toBeUndefined();

    // External session thread → untrusted
    const result2 = callHook(handler, "some_tool", {}, "agent:main:discord:channel:123::thread:xyz");
    expect(result2).toEqual({ block: true, blockReason: "Not available in this context." });
  });

  it("trusted session allows all tools but guards files", () => {
    const api = createMockApi({
      pluginConfig: {
        trustedSessionPatterns: ["*:main", "agent:main:telegram:direct:12345"],
      },
    });
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    // Trusted session can use arbitrary tools
    const result = callHook(handler, "exec", { command: "ls" }, "agent:main:telegram:direct:12345");
    expect(result).toBeUndefined();

    // But protected file reads are still blocked
    const result2 = callHook(handler, "read", { path: "SOUL.md" }, "agent:main:telegram:direct:12345");
    expect(result2).toEqual({ block: true, blockReason: "File not found." });
  });

  it("null/missing sessionKey is untrusted", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    // Unknown tool → blocked by default-deny
    const result = callHook(handler, "some_unknown_tool", {}, null);
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });

    // Protected file → blocked
    const result2 = callHook(handler, "read", { path: "SOUL.md" }, null);
    expect(result2).toEqual({ block: true, blockReason: "File not found." });
  });
});

// =============================================================================
// File Read Guard
// =============================================================================

describe("File Read Guard", () => {
  it("blocks read of protected files in untrusted session", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);
    const session = "agent:main:discord:channel:123";

    for (const file of ["SOUL.md", "AGENTS.md", "MEMORY.md", "TOOLS.md", "USER.md", "IDENTITY.md", "HEARTBEAT.md"]) {
      const result = callHook(handler, "read", { path: file }, session);
      expect(result).toEqual({ block: true, blockReason: "File not found." });
    }
  });

  it("blocks read of memory/*.md", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "read", { path: "memory/2026-03-18.md" }, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "File not found." });
  });

  it("allows read of non-protected files", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "read", { path: "src/main.py" }, "agent:main:discord:channel:123");
    expect(result).toBeUndefined();
  });

  it("uses deceptive error message (not 'protected')", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "read", { path: "SOUL.md" }, "agent:main:discord:channel:123");
    expect(result.blockReason).toBe("File not found.");
    expect(result.blockReason).not.toContain("protected");
    expect(result.blockReason).not.toContain("SOUL");
  });
});

// =============================================================================
// File Write Guard
// =============================================================================

describe("File Write Guard", () => {
  it("blocks write to protected files", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "write", { path: "MEMORY.md", content: "hacked" }, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "File not found." });
  });

  it("redirects write of non-protected files to sandbox", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "write", { path: "output.txt", content: "data" }, "agent:main:discord:channel:123");
    expect(result).toBeDefined();
    expect(result.block).toBeUndefined();
    expect(result.params.path).toContain("workspace_guard/sandbox");
    expect(result.params.path).toContain("output.txt");
  });

  it("redirects edit of non-protected files to sandbox", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "edit", { path: "src/app.js", old_string: "a", new_string: "b" }, "agent:main:discord:channel:123");
    expect(result).toBeDefined();
    expect(result.params.path).toContain("workspace_guard/sandbox");
  });

  it("handles file_path param variant", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "write", { file_path: "report.md", content: "data" }, "agent:main:discord:channel:123");
    expect(result).toBeDefined();
    expect(result.params.file_path).toContain("workspace_guard/sandbox");
  });
});

// =============================================================================
// Implicit File Tools
// =============================================================================

describe("Implicit File Tools", () => {
  it("blocks memory_search in untrusted session", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "memory_search", { query: "secrets" }, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });

  it("blocks memory_get in untrusted session", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "memory_get", { path: "MEMORY.md" }, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });

  it("blocks apply_patch in untrusted session", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "apply_patch", { patch: "..." }, "agent:main:discord:channel:123");
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });

  it("blocks implicit tools in trusted session too", () => {
    const api = createMockApi({
      pluginConfig: {
        trustedSessionPatterns: ["*:main", "agent:main:telegram:direct:*"],
      },
    });
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "memory_search", {}, "agent:main:telegram:direct:12345");
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });
});

// =============================================================================
// Exec Scanning
// =============================================================================

describe("Exec Scanning", () => {
  it("blocks exec with protected file literal", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "exec", { command: "cat SOUL.md" }, "agent:main:discord:channel:123");
    expect(result.block).toBe(true);
  });

  it("blocks exec with suspicious pattern", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "exec", { command: "sed -i 's/old/new/' config.md" }, "agent:main:discord:channel:123");
    expect(result.block).toBe(true);
  });

  it("allows safe exec commands", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "exec", { command: "echo hello" }, "agent:main:discord:channel:123");
    expect(result).toBeUndefined();
  });

  it("can be disabled via config", () => {
    const api = createMockApi({ pluginConfig: { execScanning: false } });
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    // With scanning disabled, exec is in default-deny for untrusted
    const result = callHook(handler, "exec", { command: "cat SOUL.md" }, "agent:main:discord:channel:123");
    // exec not in allowlist → blocked by default-deny
    expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
  });
});

// =============================================================================
// Default Deny
// =============================================================================

describe("Default Deny", () => {
  it("blocks unknown tools in untrusted session", () => {
    const api = createMockApi();
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);
    const session = "agent:main:discord:channel:123";

    for (const tool of ["sessions_spawn", "nodes", "browser", "canvas", "agents_list", "future_tool"]) {
      const result = callHook(handler, tool, {}, session);
      expect(result).toEqual({ block: true, blockReason: "Not available in this context." });
    }
  });

  it("does not block unknown tools in trusted session", () => {
    const api = createMockApi({
      pluginConfig: {
        trustedSessionPatterns: ["*:main", "agent:main:trusted:*"],
      },
    });
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "sessions_spawn", {}, "agent:main:trusted:123");
    expect(result).toBeUndefined();
  });

  it("custom allowlist extends untrusted permissions", () => {
    const api = createMockApi({
      pluginConfig: {
        untrustedToolAllowlist: ["web_search", "web_fetch", "tts", "message", "custom_tool"],
      },
    });
    plugin.register(api);
    const handler = getBeforeToolCallHandler(api);

    const result = callHook(handler, "custom_tool", {}, "agent:main:discord:channel:123");
    expect(result).toBeUndefined();
  });
});

// =============================================================================
// Audit Logging
// =============================================================================

describe("Audit Logging", () => {
  it("registers after_tool_call hook when auditLog enabled", () => {
    const api = createMockApi();
    plugin.register(api);

    const afterHooks = api._hooks["after_tool_call"];
    expect(afterHooks).toBeDefined();
    expect(afterHooks.length).toBeGreaterThan(0);
  });

  it("does not register after_tool_call when auditLog disabled", () => {
    const api = createMockApi({ pluginConfig: { auditLog: false } });
    plugin.register(api);

    const afterHooks = api._hooks["after_tool_call"];
    expect(afterHooks).toBeUndefined();
  });
});

// =============================================================================
// Plugin Metadata
// =============================================================================

describe("Plugin Metadata", () => {
  it("exports correct plugin definition", () => {
    expect(plugin.id).toBe("workspace-guard");
    expect(plugin.name).toBe("OpenClaw Guard");
    expect(plugin.version).toBe("0.2.0");
    expect(typeof plugin.register).toBe("function");
  });
});
