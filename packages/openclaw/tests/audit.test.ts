import { describe, it, expect, beforeEach } from "vitest";
import { AuditEntry, AuditLog } from "../src/audit.js";
import { writeFileSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("AuditEntry", () => {
  it("creates an entry with required fields", () => {
    const entry = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls -la",
      result: "allowed",
    });
    expect(entry.action).toBe("shell_command");
    expect(entry.actor).toBe("agent-1");
    expect(entry.target).toBe("ls -la");
    expect(entry.result).toBe("allowed");
    expect(entry.timestamp).toBeInstanceOf(Date);
    expect(entry.previousHash).toBeNull();
    expect(entry.metadata).toBeNull();
    expect(entry.entryHash).toBeTruthy();
    expect(entry.entryHash).toHaveLength(64); // SHA-256 hex
  });

  it("auto-computes SHA-256 hash", () => {
    const entry = new AuditEntry({
      action: "file_write",
      actor: "agent-2",
      target: "main.py",
      result: "denied",
    });
    // Hash should be 64 hex chars (SHA-256)
    expect(entry.entryHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("accepts optional previousHash and metadata", () => {
    const entry = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "git push",
      result: "allowed",
      previousHash: "abc123",
      metadata: { reason: "approved" },
    });
    expect(entry.previousHash).toBe("abc123");
    expect(entry.metadata).toEqual({ reason: "approved" });
  });

  it("produces different hashes for different content", () => {
    const entry1 = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
      timestamp: new Date("2026-01-01T00:00:00Z"),
    });
    const entry2 = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "rm",
      result: "allowed",
      timestamp: new Date("2026-01-01T00:00:00Z"),
    });
    expect(entry1.entryHash).not.toBe(entry2.entryHash);
  });

  it("produces the same hash for the same content", () => {
    const ts = new Date("2026-01-01T00:00:00.000Z");
    const entry1 = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
      timestamp: ts,
    });
    const entry2 = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
      timestamp: ts,
    });
    expect(entry1.entryHash).toBe(entry2.entryHash);
  });

  it("serializes to dict", () => {
    const ts = new Date("2026-01-01T00:00:00.000Z");
    const entry = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
      timestamp: ts,
      metadata: { key: "value" },
    });
    const dict = entry.toDict();
    expect(dict.action).toBe("shell_command");
    expect(dict.actor).toBe("agent-1");
    expect(dict.target).toBe("ls");
    expect(dict.result).toBe("allowed");
    expect(dict.timestamp).toBe(ts.toISOString());
    expect(dict.previous_hash).toBeNull();
    expect(dict.entry_hash).toBe(entry.entryHash);
    expect(dict.metadata).toEqual({ key: "value" });
  });

  it("serializes without metadata when null", () => {
    const entry = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
    });
    const dict = entry.toDict();
    expect("metadata" in dict).toBe(false);
  });

  it("deserializes from dict", () => {
    const ts = new Date("2026-01-01T00:00:00.000Z");
    const original = new AuditEntry({
      action: "shell_command",
      actor: "agent-1",
      target: "ls",
      result: "allowed",
      timestamp: ts,
      metadata: { key: "value" },
    });
    const dict = original.toDict();
    const restored = AuditEntry.fromDict(dict);
    expect(restored.action).toBe(original.action);
    expect(restored.actor).toBe(original.actor);
    expect(restored.target).toBe(original.target);
    expect(restored.result).toBe(original.result);
    expect(restored.timestamp.toISOString()).toBe(
      original.timestamp.toISOString(),
    );
    expect(restored.entryHash).toBe(original.entryHash);
    expect(restored.metadata).toEqual(original.metadata);
  });
});

describe("AuditLog", () => {
  let log: AuditLog;

  beforeEach(() => {
    log = new AuditLog("session-001");
  });

  describe("constructor", () => {
    it("stores session ID", () => {
      expect(log.sessionId).toBe("session-001");
    });

    it("starts with empty entries", () => {
      expect(log.entries).toEqual([]);
    });
  });

  describe("record", () => {
    it("records an entry and returns it", () => {
      const entry = log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      expect(entry).toBeInstanceOf(AuditEntry);
      expect(log.entries).toHaveLength(1);
    });

    it("chains entries with previous hash", () => {
      const first = log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      const second = log.record({
        action: "file_write",
        actor: "agent-1",
        target: "main.py",
        result: "denied",
      });
      expect(first.previousHash).toBeNull();
      expect(second.previousHash).toBe(first.entryHash);
    });

    it("supports optional metadata", () => {
      const entry = log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
        metadata: { duration: "5ms" },
      });
      expect(entry.metadata).toEqual({ duration: "5ms" });
    });
  });

  describe("verify", () => {
    it("returns true for an empty log", () => {
      expect(log.verify()).toBe(true);
    });

    it("returns true for an intact chain", () => {
      log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      log.record({
        action: "file_write",
        actor: "agent-1",
        target: "main.py",
        result: "allowed",
      });
      log.record({
        action: "api_call",
        actor: "agent-1",
        target: "https://api.example.com",
        result: "denied",
      });
      expect(log.verify()).toBe(true);
    });

    it("returns false when entry hash is tampered", () => {
      log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      // Tamper with the entry hash
      (log.entries[0] as { entryHash: string }).entryHash = "tampered";
      expect(log.verify()).toBe(false);
    });

    it("returns false when chain link is broken", () => {
      log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      log.record({
        action: "file_write",
        actor: "agent-1",
        target: "main.py",
        result: "allowed",
      });
      // Break the chain link
      (log.entries[1] as { previousHash: string | null }).previousHash =
        "wrong";
      expect(log.verify()).toBe(false);
    });

    it("returns false when first entry has a previous hash", () => {
      log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      (log.entries[0] as { previousHash: string | null }).previousHash =
        "should-be-null";
      expect(log.verify()).toBe(false);
    });
  });

  describe("save and load", () => {
    const testDir = join(tmpdir(), "agentguard-audit-test-" + Date.now());

    it("saves to JSONL and loads back", () => {
      mkdirSync(testDir, { recursive: true });
      const filePath = join(testDir, "audit.jsonl");

      log.record({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
      });
      log.record({
        action: "file_write",
        actor: "agent-1",
        target: "main.py",
        result: "denied",
        metadata: { reason: "policy violation" },
      });

      log.save(filePath);

      // Verify file exists and has 2 lines
      const content = readFileSync(filePath, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(2);

      // Load it back
      const loaded = AuditLog.load(filePath, "loaded-session");
      expect(loaded.sessionId).toBe("loaded-session");
      expect(loaded.entries).toHaveLength(2);
      expect(loaded.entries[0]!.action).toBe("shell_command");
      expect(loaded.entries[1]!.action).toBe("file_write");
      expect(loaded.entries[1]!.metadata).toEqual({
        reason: "policy violation",
      });
      expect(loaded.verify()).toBe(true);

      rmSync(testDir, { recursive: true, force: true });
    });

    it("throws on non-existent file", () => {
      expect(() => AuditLog.load("/nonexistent/path.jsonl", "s")).toThrow(
        "Audit log file not found",
      );
    });
  });

  describe("query", () => {
    // Use a separate log with explicit timestamps for query tests
    let queryLog: AuditLog;

    beforeEach(() => {
      queryLog = new AuditLog("query-session");
      // Manually create entries with distinct timestamps
      const e1 = new AuditEntry({
        action: "shell_command",
        actor: "agent-1",
        target: "ls",
        result: "allowed",
        timestamp: new Date("2026-01-01T00:00:00Z"),
      });
      queryLog.entries.push(e1);
      const e2 = new AuditEntry({
        action: "file_write",
        actor: "agent-2",
        target: "main.py",
        result: "denied",
        timestamp: new Date("2026-01-01T01:00:00Z"),
        previousHash: e1.entryHash,
      });
      queryLog.entries.push(e2);
      const e3 = new AuditEntry({
        action: "shell_command",
        actor: "agent-1",
        target: "git push",
        result: "denied",
        timestamp: new Date("2026-01-01T02:00:00Z"),
        previousHash: e2.entryHash,
      });
      queryLog.entries.push(e3);
    });

    it("returns all entries with no filters", () => {
      expect(queryLog.query({})).toHaveLength(3);
    });

    it("filters by action", () => {
      const results = queryLog.query({ action: "shell_command" });
      expect(results).toHaveLength(2);
      expect(results.every((e) => e.action === "shell_command")).toBe(true);
    });

    it("filters by actor", () => {
      const results = queryLog.query({ actor: "agent-2" });
      expect(results).toHaveLength(1);
      expect(results[0]!.actor).toBe("agent-2");
    });

    it("filters by result", () => {
      const results = queryLog.query({ result: "denied" });
      expect(results).toHaveLength(2);
    });

    it("combines filters with AND logic", () => {
      const results = queryLog.query({
        action: "shell_command",
        result: "denied",
      });
      expect(results).toHaveLength(1);
      expect(results[0]!.target).toBe("git push");
    });

    it("filters by after timestamp", () => {
      // Everything after 00:00 (exclusive) => 01:00 and 02:00
      const results = queryLog.query({
        after: new Date("2026-01-01T00:00:00Z"),
      });
      expect(results).toHaveLength(2);
    });

    it("filters by before timestamp", () => {
      // Everything before 02:00 (exclusive) => 00:00 and 01:00
      const results = queryLog.query({
        before: new Date("2026-01-01T02:00:00Z"),
      });
      expect(results).toHaveLength(2);
    });

    it("returns empty for no matches", () => {
      const results = queryLog.query({ action: "api_call" });
      expect(results).toHaveLength(0);
    });
  });
});
