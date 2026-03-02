/**
 * OpenClaw plugin definition for AgentGuard.
 *
 * Integrates AgentGuard's policy engine and audit log into OpenClaw's
 * hook system via `before_tool_call` and `after_tool_call` hooks.
 *
 * @license AGPL-3.0-or-later
 */

import { Guard } from "./guard.js";
import { AuditLog } from "./audit.js";
import type { Decision, Policy } from "./models.js";

/** Event payload for the before_tool_call hook. */
export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

/** Result returned from the before_tool_call hook. */
export interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

/** Event payload for the after_tool_call hook. */
export interface AfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

/** Configuration options for the AgentGuard plugin. */
export interface AgentGuardPluginOptions {
  /** Policies to enforce. */
  policies?: readonly Policy[];
  /** Session ID for the audit log. Defaults to a timestamp-based ID. */
  sessionId?: string;
  /** Actor name for audit entries. Defaults to "agent". */
  actor?: string;
  /** Callback invoked when an action is denied. */
  onDeny?: (decision: Decision, event: BeforeToolCallEvent) => void;
}

/** The AgentGuard plugin instance. */
export interface AgentGuardPlugin {
  /** Plugin name. */
  readonly name: string;
  /** Plugin version. */
  readonly version: string;
  /** The underlying Guard instance. */
  readonly guard: Guard;
  /** The underlying AuditLog instance. */
  readonly auditLog: AuditLog;
  /** Hook handler for before_tool_call. */
  beforeToolCall(event: BeforeToolCallEvent): BeforeToolCallResult;
  /** Hook handler for after_tool_call. */
  afterToolCall(event: AfterToolCallEvent): void;
}

/**
 * Create an AgentGuard plugin for OpenClaw.
 *
 * @example
 * ```ts
 * import { createAgentGuardPlugin } from "@agentguard/openclaw";
 *
 * const plugin = createAgentGuardPlugin({
 *   policies: [myPolicy],
 *   actor: "my-agent",
 * });
 *
 * // Register with OpenClaw:
 * // api.registerHook("before_tool_call", plugin.beforeToolCall);
 * // api.registerHook("after_tool_call", plugin.afterToolCall);
 * ```
 */
export function createAgentGuardPlugin(
  options: AgentGuardPluginOptions,
): AgentGuardPlugin {
  const guard = new Guard(options.policies);
  const sessionId =
    options.sessionId ?? `agentguard-${Date.now()}`;
  const auditLog = new AuditLog(sessionId);
  const actor = options.actor ?? "agent";
  const onDeny = options.onDeny;

  function beforeToolCall(event: BeforeToolCallEvent): BeforeToolCallResult {
    const decision = guard.check(event.toolName, event.params);

    auditLog.record({
      action: event.toolName,
      actor,
      target: summarizeParams(event.params),
      result: decision.allowed ? "allowed" : "denied",
      metadata: decision.allowed
        ? undefined
        : {
            deniedBy: decision.deniedBy ?? "",
            reason: decision.reason ?? "",
          },
    });

    if (!decision.allowed) {
      onDeny?.(decision, event);
      return {
        block: true,
        blockReason: decision.reason ?? "Blocked by AgentGuard",
      };
    }

    return { block: false };
  }

  function afterToolCall(event: AfterToolCallEvent): void {
    const metadata: Record<string, string> = {};
    if (event.error !== undefined) {
      metadata["error"] = event.error;
    }
    if (event.durationMs !== undefined) {
      metadata["durationMs"] = String(event.durationMs);
    }

    auditLog.record({
      action: event.toolName,
      actor,
      target: summarizeParams(event.params),
      result: event.error !== undefined ? "error" : "completed",
      metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
    });
  }

  return {
    name: "agentguard",
    version: "0.1.0",
    guard,
    auditLog,
    beforeToolCall,
    afterToolCall,
  };
}

/** Produce a short summary of params for the audit target field. */
function summarizeParams(params: Record<string, unknown>): string {
  const entries = Object.entries(params);
  if (entries.length === 0) return "";
  const first = entries[0]!;
  const value = typeof first[1] === "string" ? first[1] : JSON.stringify(first[1]);
  if (value.length > 200) {
    return value.slice(0, 200) + "...";
  }
  return value;
}
