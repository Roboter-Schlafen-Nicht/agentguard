import { describe, it, expect } from "vitest";
import { loadPolicyFromString, loadPolicyFromFile } from "../src/loader.js";
import { Severity } from "../src/models.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("loadPolicyFromString", () => {
  it("parses a valid policy YAML string", () => {
    const yaml = `
name: test-policy
description: A test policy
rules:
  - action: shell_command
    deny:
      - pattern: 'git push.*--force'
    severity: critical
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.name).toBe("test-policy");
    expect(policy.description).toBe("A test policy");
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0]!.actionKind).toBe("shell_command");
    expect(policy.rules[0]!.severity).toBe(Severity.CRITICAL);
    expect(policy.rules[0]!.denyPatterns).toHaveLength(1);
  });

  it("compiles regex patterns correctly", () => {
    const yaml = `
name: regex-test
rules:
  - action: shell_command
    deny:
      - pattern: 'rm\\s+-rf'
    severity: high
`;
    const policy = loadPolicyFromString(yaml);
    const pattern = policy.rules[0]!.denyPatterns[0]!;
    expect(pattern.test("rm -rf /")).toBe(true);
    expect(pattern.test("echo hello")).toBe(false);
  });

  it("parses multiple rules", () => {
    const yaml = `
name: multi-rule
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
    severity: high
  - action: file_write
    deny:
      - pattern: '\\.env$'
    severity: critical
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.rules).toHaveLength(2);
    expect(policy.rules[0]!.actionKind).toBe("shell_command");
    expect(policy.rules[1]!.actionKind).toBe("file_write");
  });

  it("parses rule descriptions", () => {
    const yaml = `
name: desc-test
rules:
  - action: shell_command
    description: Block force push
    deny:
      - pattern: 'force'
    severity: critical
`;
    const policy = loadPolicyFromString(yaml);
    expect(policy.rules[0]!.description).toBe("Block force push");
  });

  it("throws on non-mapping YAML", () => {
    expect(() => loadPolicyFromString("just a string")).toThrow(
      "Policy YAML must be a mapping",
    );
  });

  it("throws on missing name", () => {
    const yaml = `
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Policy must have a 'name' field",
    );
  });

  it("throws on missing rules", () => {
    const yaml = `
name: no-rules
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Policy must have a non-empty 'rules' field",
    );
  });

  it("throws on empty rules", () => {
    const yaml = `
name: empty-rules
rules: []
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Policy must have a non-empty 'rules' field",
    );
  });

  it("throws on non-mapping rule", () => {
    const yaml = `
name: bad-rule
rules:
  - just a string
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each rule must be a mapping",
    );
  });

  it("throws on missing action field in rule", () => {
    const yaml = `
name: no-action
rules:
  - deny:
      - pattern: 'rm'
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each rule must have an 'action' field",
    );
  });

  it("throws on missing deny field in rule", () => {
    const yaml = `
name: no-deny
rules:
  - action: shell_command
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each rule must have a non-empty 'deny' field",
    );
  });

  it("throws on missing severity field in rule", () => {
    const yaml = `
name: no-severity
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each rule must have a 'severity' field",
    );
  });

  it("throws on invalid severity value", () => {
    const yaml = `
name: bad-severity
rules:
  - action: shell_command
    deny:
      - pattern: 'rm'
    severity: extreme
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Invalid severity 'extreme'",
    );
  });

  it("throws on deny entry without pattern key", () => {
    const yaml = `
name: no-pattern
rules:
  - action: shell_command
    deny:
      - regex: 'rm'
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each deny entry must have a 'pattern' key",
    );
  });

  it("throws on non-mapping deny entry", () => {
    const yaml = `
name: bad-deny
rules:
  - action: shell_command
    deny:
      - just_a_string
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(
      "Each deny entry must be a mapping with a 'pattern' key",
    );
  });

  it("throws on invalid regex pattern", () => {
    const yaml = `
name: bad-regex
rules:
  - action: shell_command
    deny:
      - pattern: '(?P<invalid>'
    severity: high
`;
    expect(() => loadPolicyFromString(yaml)).toThrow(/Invalid regex pattern/);
  });
});

describe("loadPolicyFromFile", () => {
  const testDir = join(tmpdir(), "agentguard-loader-test-" + Date.now());

  it("loads a valid policy from a YAML file", () => {
    mkdirSync(testDir, { recursive: true });
    const filePath = join(testDir, "test-policy.yaml");
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
    const policy = loadPolicyFromFile(filePath);
    expect(policy.name).toBe("file-policy");
    expect(policy.rules).toHaveLength(1);

    // Cleanup
    rmSync(testDir, { recursive: true, force: true });
  });

  it("throws on non-existent file", () => {
    expect(() => loadPolicyFromFile("/nonexistent/path.yaml")).toThrow(
      "Policy file not found",
    );
  });
});
