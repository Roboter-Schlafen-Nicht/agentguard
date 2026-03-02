import { describe, it, expect } from "vitest";
import { Guard } from "../src/guard.js";
import { Severity, type Policy } from "../src/models.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("Guard", () => {
  const forcePolicy: Policy = {
    name: "no-force-push",
    rules: [
      {
        actionKind: "shell_command",
        denyPatterns: [/git push\s+.*--force/],
        severity: Severity.CRITICAL,
      },
    ],
  };

  const secretPolicy: Policy = {
    name: "no-secrets",
    rules: [
      {
        actionKind: "file_write",
        denyPatterns: [/\.env$/],
        severity: Severity.HIGH,
      },
    ],
  };

  describe("constructor", () => {
    it("starts with empty policies by default", () => {
      const guard = new Guard();
      expect(guard.policies).toEqual([]);
    });

    it("accepts initial policies", () => {
      const guard = new Guard([forcePolicy]);
      expect(guard.policies).toHaveLength(1);
      expect(guard.policies[0]!.name).toBe("no-force-push");
    });
  });

  describe("addPolicy", () => {
    it("adds a policy and returns self for chaining", () => {
      const guard = new Guard();
      const result = guard.addPolicy(forcePolicy);
      expect(result).toBe(guard);
      expect(guard.policies).toHaveLength(1);
    });

    it("allows chaining multiple policies", () => {
      const guard = new Guard();
      guard.addPolicy(forcePolicy).addPolicy(secretPolicy);
      expect(guard.policies).toHaveLength(2);
    });
  });

  describe("loadPolicyString", () => {
    it("loads a policy from YAML string and returns self", () => {
      const guard = new Guard();
      const result = guard.loadPolicyString(`
name: yaml-policy
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
    severity: high
`);
      expect(result).toBe(guard);
      expect(guard.policies).toHaveLength(1);
      expect(guard.policies[0]!.name).toBe("yaml-policy");
    });
  });

  describe("loadPolicyFile", () => {
    const testDir = join(tmpdir(), "agentguard-guard-test-" + Date.now());

    it("loads a policy from a YAML file and returns self", () => {
      mkdirSync(testDir, { recursive: true });
      const filePath = join(testDir, "test.yaml");
      writeFileSync(
        filePath,
        `
name: file-policy
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
    severity: high
`,
      );
      const guard = new Guard();
      const result = guard.loadPolicyFile(filePath);
      expect(result).toBe(guard);
      expect(guard.policies).toHaveLength(1);
      expect(guard.policies[0]!.name).toBe("file-policy");

      rmSync(testDir, { recursive: true, force: true });
    });
  });

  describe("check", () => {
    it("allows actions when no policies are loaded", () => {
      const guard = new Guard();
      const decision = guard.check("shell_command", { command: "rm -rf /" });
      expect(decision.allowed).toBe(true);
    });

    it("allows actions that match no rules", () => {
      const guard = new Guard([forcePolicy]);
      const decision = guard.check("shell_command", {
        command: "git push origin main",
      });
      expect(decision.allowed).toBe(true);
    });

    it("denies actions that match a rule", () => {
      const guard = new Guard([forcePolicy]);
      const decision = guard.check("shell_command", {
        command: "git push origin --force main",
      });
      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy).toBe("no-force-push");
      expect(decision.reason).toBe("Blocked by policy: no-force-push");
      expect(decision.severity).toBe(Severity.CRITICAL);
    });

    it("checks against all policies and first deny wins", () => {
      const guard = new Guard([forcePolicy, secretPolicy]);
      // Matches secretPolicy
      const decision = guard.check("file_write", { path: "config/.env" });
      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy).toBe("no-secrets");
    });

    it("allows actions that do not match any policy", () => {
      const guard = new Guard([forcePolicy, secretPolicy]);
      const decision = guard.check("api_call", {
        url: "https://example.com",
      });
      expect(decision.allowed).toBe(true);
    });
  });
});
