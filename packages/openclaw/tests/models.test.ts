import { describe, it, expect } from "vitest";
import {
  Severity,
  compareSeverity,
  type Action,
  type Rule,
  type Decision,
  type Policy,
  matchesRule,
  evaluatePolicy,
} from "../src/models.js";

describe("Severity", () => {
  it("has four levels", () => {
    expect(Severity.LOW).toBe("low");
    expect(Severity.MEDIUM).toBe("medium");
    expect(Severity.HIGH).toBe("high");
    expect(Severity.CRITICAL).toBe("critical");
  });

  it("compareSeverity orders LOW < MEDIUM < HIGH < CRITICAL", () => {
    expect(compareSeverity(Severity.LOW, Severity.MEDIUM)).toBeLessThan(0);
    expect(compareSeverity(Severity.MEDIUM, Severity.HIGH)).toBeLessThan(0);
    expect(compareSeverity(Severity.HIGH, Severity.CRITICAL)).toBeLessThan(0);
    expect(compareSeverity(Severity.LOW, Severity.CRITICAL)).toBeLessThan(0);
  });

  it("compareSeverity returns 0 for equal severities", () => {
    expect(compareSeverity(Severity.LOW, Severity.LOW)).toBe(0);
    expect(compareSeverity(Severity.CRITICAL, Severity.CRITICAL)).toBe(0);
  });

  it("compareSeverity returns positive for higher > lower", () => {
    expect(compareSeverity(Severity.CRITICAL, Severity.LOW)).toBeGreaterThan(0);
    expect(compareSeverity(Severity.HIGH, Severity.MEDIUM)).toBeGreaterThan(0);
  });
});

describe("Action", () => {
  it("has kind and params", () => {
    const action: Action = { kind: "shell_command", params: { command: "ls" } };
    expect(action.kind).toBe("shell_command");
    expect(action.params).toEqual({ command: "ls" });
  });

  it("allows empty params", () => {
    const action: Action = { kind: "noop", params: {} };
    expect(action.params).toEqual({});
  });
});

describe("Rule", () => {
  it("has required fields", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/git push.*--force/],
      severity: Severity.CRITICAL,
    };
    expect(rule.actionKind).toBe("shell_command");
    expect(rule.denyPatterns).toHaveLength(1);
    expect(rule.severity).toBe(Severity.CRITICAL);
    expect(rule.description).toBeUndefined();
  });

  it("accepts optional description", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [],
      severity: Severity.LOW,
      description: "Test rule",
    };
    expect(rule.description).toBe("Test rule");
  });
});

describe("matchesRule", () => {
  it("returns false when action kind does not match", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/rm/],
      severity: Severity.HIGH,
    };
    const action: Action = { kind: "file_write", params: { content: "rm -rf" } };
    expect(matchesRule(rule, action)).toBe(false);
  });

  it("returns true when kind matches and a pattern matches a param value", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/git push\s+.*--force/],
      severity: Severity.CRITICAL,
    };
    const action: Action = {
      kind: "shell_command",
      params: { command: "git push origin --force" },
    };
    expect(matchesRule(rule, action)).toBe(true);
  });

  it("returns false when kind matches but no pattern matches", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/git push\s+.*--force/],
      severity: Severity.CRITICAL,
    };
    const action: Action = {
      kind: "shell_command",
      params: { command: "git push origin main" },
    };
    expect(matchesRule(rule, action)).toBe(false);
  });

  it("checks all param values against all patterns", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/rm/, /DROP/],
      severity: Severity.HIGH,
    };
    // Second param matches second pattern
    const action: Action = {
      kind: "shell_command",
      params: { cmd: "echo hello", sql: "DROP TABLE users" },
    };
    expect(matchesRule(rule, action)).toBe(true);
  });

  it("returns false for empty params", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/rm/],
      severity: Severity.HIGH,
    };
    const action: Action = { kind: "shell_command", params: {} };
    expect(matchesRule(rule, action)).toBe(false);
  });

  it("only checks string param values", () => {
    const rule: Rule = {
      actionKind: "shell_command",
      denyPatterns: [/rm/],
      severity: Severity.HIGH,
    };
    // Params with non-string values should be skipped entirely
    const action: Action = {
      kind: "shell_command",
      params: {
        count: 42 as unknown,
        flag: true as unknown,
        metadata: { command: "rm -rf" } as unknown,
        note: "safe",
      },
    };
    expect(matchesRule(rule, action)).toBe(false);
  });
});

describe("Decision", () => {
  it("represents an allowed decision", () => {
    const decision: Decision = { allowed: true };
    expect(decision.allowed).toBe(true);
    expect(decision.deniedBy).toBeUndefined();
    expect(decision.reason).toBeUndefined();
    expect(decision.severity).toBeUndefined();
  });

  it("represents a denied decision", () => {
    const decision: Decision = {
      allowed: false,
      deniedBy: "no-force-push",
      reason: "Blocked by policy: no-force-push",
      severity: Severity.CRITICAL,
    };
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toBe("no-force-push");
    expect(decision.reason).toBe("Blocked by policy: no-force-push");
    expect(decision.severity).toBe(Severity.CRITICAL);
  });
});

describe("Policy", () => {
  it("has name, rules, and optional description", () => {
    const policy: Policy = {
      name: "test-policy",
      rules: [],
    };
    expect(policy.name).toBe("test-policy");
    expect(policy.rules).toEqual([]);
    expect(policy.description).toBeUndefined();
  });
});

describe("evaluatePolicy", () => {
  const policy: Policy = {
    name: "test-policy",
    description: "A test policy",
    rules: [
      {
        actionKind: "shell_command",
        denyPatterns: [/git push\s+.*--force/],
        severity: Severity.CRITICAL,
        description: "No force push",
      },
      {
        actionKind: "file_write",
        denyPatterns: [/\.env$/],
        severity: Severity.HIGH,
        description: "No env files",
      },
    ],
  };

  it("allows actions that match no rules", () => {
    const action: Action = {
      kind: "shell_command",
      params: { command: "git push origin main" },
    };
    const decision = evaluatePolicy(policy, action);
    expect(decision.allowed).toBe(true);
  });

  it("denies actions that match a rule", () => {
    const action: Action = {
      kind: "shell_command",
      params: { command: "git push origin --force main" },
    };
    const decision = evaluatePolicy(policy, action);
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toBe("test-policy");
    expect(decision.reason).toBe("Blocked by policy: test-policy");
    expect(decision.severity).toBe(Severity.CRITICAL);
  });

  it("returns first matching rule's decision (short circuit)", () => {
    // Both rules match, but we should get the first one
    const multiPolicy: Policy = {
      name: "multi",
      rules: [
        {
          actionKind: "shell_command",
          denyPatterns: [/rm/],
          severity: Severity.HIGH,
        },
        {
          actionKind: "shell_command",
          denyPatterns: [/rm/],
          severity: Severity.LOW,
        },
      ],
    };
    const action: Action = {
      kind: "shell_command",
      params: { command: "rm -rf /" },
    };
    const decision = evaluatePolicy(multiPolicy, action);
    expect(decision.severity).toBe(Severity.HIGH);
  });

  it("allows all actions when policy has no matching rules for the kind", () => {
    const action: Action = {
      kind: "api_call",
      params: { url: "https://example.com" },
    };
    const decision = evaluatePolicy(policy, action);
    expect(decision.allowed).toBe(true);
  });
});
