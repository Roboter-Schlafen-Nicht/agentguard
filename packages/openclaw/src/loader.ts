/**
 * YAML policy loader and validator.
 *
 * Parses YAML policy definitions into Policy objects. Validates structure,
 * required fields, regex patterns, and severity values.
 *
 * @license AGPL-3.0-or-later
 */

import { readFileSync, existsSync } from "node:fs";
import yaml from "js-yaml";
import { Severity, type Policy, type Rule } from "./models.js";

const VALID_SEVERITIES = new Set<string>(Object.values(Severity));

/**
 * Parse a YAML string into a Policy object.
 *
 * @param yamlStr - YAML-formatted policy definition.
 * @returns A validated Policy object.
 * @throws {Error} If the YAML is missing required fields or has invalid values.
 */
export function loadPolicyFromString(yamlStr: string): Policy {
  const data: unknown = yaml.load(yamlStr);
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("Policy YAML must be a mapping");
  }
  return parsePolicy(data as Record<string, unknown>);
}

/**
 * Load a policy from a YAML file.
 *
 * @param path - Path to the YAML file.
 * @returns A validated Policy object.
 * @throws {Error} If the file does not exist or YAML is invalid.
 */
export function loadPolicyFromFile(path: string): Policy {
  if (!existsSync(path)) {
    throw new Error(`Policy file not found: ${path}`);
  }
  const text = readFileSync(path, "utf-8");
  return loadPolicyFromString(text);
}

function parsePolicy(data: Record<string, unknown>): Policy {
  if (!("name" in data) || typeof data["name"] !== "string") {
    throw new Error("Policy must have a 'name' field");
  }

  if (
    !("rules" in data) ||
    !Array.isArray(data["rules"]) ||
    data["rules"].length === 0
  ) {
    throw new Error("Policy must have a non-empty 'rules' field");
  }

  const rules = (data["rules"] as unknown[]).map((r) => parseRule(r));
  return {
    name: data["name"],
    description:
      typeof data["description"] === "string" ? data["description"] : undefined,
    rules,
  };
}

function parseRule(data: unknown): Rule {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("Each rule must be a mapping");
  }

  const record = data as Record<string, unknown>;

  if (!("action" in record) || typeof record["action"] !== "string") {
    throw new Error("Each rule must have an 'action' field");
  }

  if (
    !("deny" in record) ||
    !Array.isArray(record["deny"]) ||
    record["deny"].length === 0
  ) {
    throw new Error("Each rule must have a non-empty 'deny' field");
  }

  if (!("severity" in record) || typeof record["severity"] !== "string") {
    throw new Error("Each rule must have a 'severity' field");
  }

  const severity = parseSeverity(record["severity"]);
  const patterns = (record["deny"] as unknown[]).map((p) => parsePattern(p));

  return {
    actionKind: record["action"],
    denyPatterns: patterns,
    severity,
    description:
      typeof record["description"] === "string"
        ? record["description"]
        : undefined,
  };
}

function parseSeverity(value: string): Severity {
  if (!VALID_SEVERITIES.has(value)) {
    const valid = Object.values(Severity).join(", ");
    throw new Error(`Invalid severity '${value}'. Valid values: ${valid}`);
  }
  return value as Severity;
}

function parsePattern(data: unknown): RegExp {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("Each deny entry must be a mapping with a 'pattern' key");
  }

  const record = data as Record<string, unknown>;

  if (!("pattern" in record) || typeof record["pattern"] !== "string") {
    throw new Error("Each deny entry must have a 'pattern' key");
  }

  try {
    return new RegExp(record["pattern"]);
  } catch (e) {
    const msg =
      e instanceof Error ? e.message : String(e);
    throw new Error(`Invalid regex pattern '${record["pattern"]}': ${msg}`);
  }
}
