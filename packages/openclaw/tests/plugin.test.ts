import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  createAgentGuardPlugin,
  type AgentGuardPluginOptions,
  type BeforeToolCallEvent,
  type BeforeToolCallResult,
  type AfterToolCallEvent,
} from "../src/plugin.js";
import { Severity, type Policy } from "../src/models.js";

describe("createAgentGuardPlugin", () => {
  const denyPolicy: Policy = {
    name: "no-force-push",
    rules: [
      {
        actionKind: "shell_command",
        denyPatterns: [/git push\s+.*--force/],
        severity: Severity.CRITICAL,
      },
    ],
  };

  describe("plugin metadata", () => {
    it("returns a plugin definition with name and version", () => {
      const plugin = createAgentGuardPlugin({});
      expect(plugin.name).toBe("agentguard");
      expect(plugin.version).toBeTruthy();
    });

    it("version is a valid semver-like string", () => {
      const plugin = createAgentGuardPlugin({});
      // Should be "0.0.0-dev" in test (define not injected) or a real version
      expect(plugin.version).toMatch(/^\d+\.\d+\.\d+/);
    });
  });

  describe("beforeToolCall hook", () => {
    it("allows actions that match no rules", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "git push origin main" },
      };
      const result = plugin.beforeToolCall(event);
      expect(result.block).toBe(false);
    });

    it("blocks actions that match a deny rule", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "git push origin --force main" },
      };
      const result = plugin.beforeToolCall(event);
      expect(result.block).toBe(true);
      expect(result.blockReason).toContain("no-force-push");
    });

    it("logs allowed actions to audit log", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "ls -la" },
      };
      plugin.beforeToolCall(event);
      const entries = plugin.auditLog.entries;
      expect(entries).toHaveLength(1);
      expect(entries[0]!.result).toBe("allowed");
      expect(entries[0]!.action).toBe("shell_command");
    });

    it("logs denied actions to audit log", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "git push origin --force main" },
      };
      plugin.beforeToolCall(event);
      const entries = plugin.auditLog.entries;
      expect(entries).toHaveLength(1);
      expect(entries[0]!.result).toBe("denied");
    });

    it("works with no policies (allows everything)", () => {
      const plugin = createAgentGuardPlugin({});
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "rm -rf /" },
      };
      const result = plugin.beforeToolCall(event);
      expect(result.block).toBe(false);
    });

    it("does not modify params", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "ls" },
      };
      const result = plugin.beforeToolCall(event);
      expect(result.params).toBeUndefined();
    });
  });

  describe("afterToolCall hook", () => {
    it("logs successful tool calls", () => {
      const plugin = createAgentGuardPlugin({});
      const event: AfterToolCallEvent = {
        toolName: "shell_command",
        params: { command: "ls" },
        result: "file1.txt\nfile2.txt",
        durationMs: 42,
      };
      plugin.afterToolCall(event);
      const entries = plugin.auditLog.entries;
      expect(entries).toHaveLength(1);
      expect(entries[0]!.action).toBe("shell_command");
      expect(entries[0]!.result).toBe("completed");
      expect(entries[0]!.metadata).toEqual({ durationMs: "42" });
    });

    it("logs errored tool calls", () => {
      const plugin = createAgentGuardPlugin({});
      const event: AfterToolCallEvent = {
        toolName: "shell_command",
        params: { command: "failing-command" },
        error: "Command not found",
        durationMs: 5,
      };
      plugin.afterToolCall(event);
      const entries = plugin.auditLog.entries;
      expect(entries).toHaveLength(1);
      expect(entries[0]!.result).toBe("error");
      expect(entries[0]!.metadata).toEqual({
        error: "Command not found",
        durationMs: "5",
      });
    });

    it("handles missing optional fields", () => {
      const plugin = createAgentGuardPlugin({});
      const event: AfterToolCallEvent = {
        toolName: "shell_command",
        params: { command: "ls" },
      };
      plugin.afterToolCall(event);
      const entries = plugin.auditLog.entries;
      expect(entries).toHaveLength(1);
      expect(entries[0]!.result).toBe("completed");
    });
  });

  describe("onDeny callback", () => {
    it("calls the onDeny callback when an action is blocked", () => {
      const onDeny = vi.fn();
      const plugin = createAgentGuardPlugin({
        policies: [denyPolicy],
        onDeny,
      });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "git push origin --force main" },
      };
      plugin.beforeToolCall(event);
      expect(onDeny).toHaveBeenCalledOnce();
      expect(onDeny).toHaveBeenCalledWith(
        expect.objectContaining({
          allowed: false,
          deniedBy: "no-force-push",
        }),
        event,
      );
    });

    it("does not call onDeny when action is allowed", () => {
      const onDeny = vi.fn();
      const plugin = createAgentGuardPlugin({
        policies: [denyPolicy],
        onDeny,
      });
      const event: BeforeToolCallEvent = {
        toolName: "shell_command",
        params: { command: "ls" },
      };
      plugin.beforeToolCall(event);
      expect(onDeny).not.toHaveBeenCalled();
    });
  });

  describe("custom sessionId and actor", () => {
    it("uses provided sessionId", () => {
      const plugin = createAgentGuardPlugin({
        sessionId: "custom-session",
      });
      expect(plugin.auditLog.sessionId).toBe("custom-session");
    });

    it("uses provided actor in audit entries", () => {
      const plugin = createAgentGuardPlugin({ actor: "my-agent" });
      plugin.beforeToolCall({
        toolName: "shell_command",
        params: { command: "ls" },
      });
      expect(plugin.auditLog.entries[0]!.actor).toBe("my-agent");
    });

    it("defaults actor to 'agent'", () => {
      const plugin = createAgentGuardPlugin({});
      plugin.beforeToolCall({
        toolName: "shell_command",
        params: { command: "ls" },
      });
      expect(plugin.auditLog.entries[0]!.actor).toBe("agent");
    });
  });

  describe("guard access", () => {
    it("exposes the underlying guard", () => {
      const plugin = createAgentGuardPlugin({ policies: [denyPolicy] });
      expect(plugin.guard.policies).toHaveLength(1);
    });
  });

  describe("audit log integrity", () => {
    it("maintains hash chain across before and after calls", () => {
      const plugin = createAgentGuardPlugin({});

      plugin.beforeToolCall({
        toolName: "shell_command",
        params: { command: "ls" },
      });
      plugin.afterToolCall({
        toolName: "shell_command",
        params: { command: "ls" },
        result: "output",
        durationMs: 10,
      });
      plugin.beforeToolCall({
        toolName: "file_write",
        params: { path: "test.txt" },
      });

      expect(plugin.auditLog.entries).toHaveLength(3);
      expect(plugin.auditLog.verify()).toBe(true);
    });
  });

  describe("summarizeParams resilience", () => {
    it("handles empty params", () => {
      const plugin = createAgentGuardPlugin({});
      plugin.beforeToolCall({ toolName: "noop", params: {} });
      expect(plugin.auditLog.entries[0]!.target).toBe("");
    });

    it("handles non-string param values (number)", () => {
      const plugin = createAgentGuardPlugin({});
      plugin.beforeToolCall({
        toolName: "api_call",
        params: { timeout: 5000 },
      });
      expect(plugin.auditLog.entries[0]!.target).toBe("5000");
    });

    it("handles undefined param values gracefully", () => {
      const plugin = createAgentGuardPlugin({});
      plugin.beforeToolCall({
        toolName: "api_call",
        params: { value: undefined },
      });
      // JSON.stringify(undefined) returns undefined, so fallback to String()
      const target = plugin.auditLog.entries[0]!.target;
      expect(target).toBe("undefined");
    });

    it("truncates long param values to 200 chars", () => {
      const plugin = createAgentGuardPlugin({});
      const longString = "x".repeat(300);
      plugin.beforeToolCall({
        toolName: "shell_command",
        params: { command: longString },
      });
      expect(plugin.auditLog.entries[0]!.target).toHaveLength(203); // 200 + "..."
      expect(plugin.auditLog.entries[0]!.target).toMatch(/\.\.\.$/);
    });
  });
});
