/**
 * Policy data models: Severity, Action, Rule, Decision, Policy.
 *
 * These are the core types used throughout the AgentGuard policy engine.
 * TypeScript port of the Python reference implementation.
 *
 * @license AGPL-3.0-or-later
 */

/** Risk severity level for a policy rule. Ordered: LOW < MEDIUM < HIGH < CRITICAL. */
export const Severity = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

const SEVERITY_ORDER: readonly Severity[] = [
  Severity.LOW,
  Severity.MEDIUM,
  Severity.HIGH,
  Severity.CRITICAL,
];

/**
 * Compare two severity values.
 * Returns negative if a < b, 0 if equal, positive if a > b.
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}

/** An action an agent wants to perform. */
export interface Action {
  /** The type of action (e.g. "shell_command", "file_write"). */
  readonly kind: string;
  /** Key-value parameters for the action. */
  readonly params: Record<string, unknown>;
}

/** A deny rule within a policy. */
export interface Rule {
  /** The kind of action this rule applies to. */
  readonly actionKind: string;
  /** Compiled regex patterns. If any matches any param value, the action is denied. */
  readonly denyPatterns: readonly RegExp[];
  /** How severe a violation of this rule is. */
  readonly severity: Severity;
  /** Optional human-readable description. */
  readonly description?: string;
}

/** The result of evaluating an action against a policy. */
export interface Decision {
  /** Whether the action is allowed. */
  readonly allowed: boolean;
  /** Name of the policy that denied it (if denied). */
  readonly deniedBy?: string;
  /** Human-readable explanation (if denied). */
  readonly reason?: string;
  /** Severity of the violated rule (if denied). */
  readonly severity?: Severity;
}

/** A named collection of rules that govern agent behavior. */
export interface Policy {
  /** Unique identifier for this policy. */
  readonly name: string;
  /** List of deny rules. First match wins. */
  readonly rules: readonly Rule[];
  /** Human-readable description. */
  readonly description?: string;
}

/**
 * Check if a rule matches the given action.
 *
 * A rule matches if:
 * 1. The action's kind matches the rule's actionKind
 * 2. Any deny pattern matches any string value in the action's params
 */
export function matchesRule(rule: Rule, action: Action): boolean {
  if (action.kind !== rule.actionKind) {
    return false;
  }
  for (const pattern of rule.denyPatterns) {
    for (const value of Object.values(action.params)) {
      if (typeof value === "string" && pattern.test(value)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Evaluate an action against all rules in a policy.
 *
 * Returns the first matching rule's decision, or allows if none match.
 */
export function evaluatePolicy(policy: Policy, action: Action): Decision {
  for (const rule of policy.rules) {
    if (matchesRule(rule, action)) {
      return {
        allowed: false,
        deniedBy: policy.name,
        reason: `Blocked by policy: ${policy.name}`,
        severity: rule.severity,
      };
    }
  }
  return { allowed: true };
}
