/**
 * @agentguard/openclaw — AgentGuard policy engine and audit logging for OpenClaw.
 *
 * TypeScript-native port of AgentGuard's core policy engine, audit log,
 * and OpenClaw plugin integration. Zero Python dependency.
 *
 * @license AGPL-3.0-or-later
 * @packageDocumentation
 */

// Models
export {
  Severity,
  compareSeverity,
  matchesRule,
  evaluatePolicy,
  type Action,
  type Rule,
  type Decision,
  type Policy,
} from "./models.js";

// Loader
export { loadPolicyFromString, loadPolicyFromFile } from "./loader.js";

// Guard
export { Guard } from "./guard.js";

// Audit
export {
  AuditEntry,
  AuditLog,
  type AuditEntryInit,
  type AuditEntryDict,
  type AuditQueryFilter,
  type AuditRecordInit,
} from "./audit.js";

// Plugin
export {
  createAgentGuardPlugin,
  type AgentGuardPlugin,
  type AgentGuardPluginOptions,
  type BeforeToolCallEvent,
  type BeforeToolCallResult,
  type AfterToolCallEvent,
} from "./plugin.js";
