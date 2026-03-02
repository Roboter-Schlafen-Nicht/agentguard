/**
 * Audit entry and hash-chained audit log.
 *
 * AuditEntry represents a single logged event. AuditLog manages a
 * tamper-evident, append-only log with hash chaining using SHA-256.
 *
 * @license AGPL-3.0-or-later
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

/** Constructor options for AuditEntry. */
export interface AuditEntryInit {
  action: string;
  actor: string;
  target: string;
  result: string;
  timestamp?: Date;
  previousHash?: string | null;
  metadata?: Record<string, string> | null;
  entryHash?: string;
}

/** Serialized form of an AuditEntry (for JSON output). */
export interface AuditEntryDict {
  action: string;
  actor: string;
  target: string;
  result: string;
  timestamp: string;
  previous_hash: string | null;
  entry_hash: string;
  metadata?: Record<string, string>;
}

/**
 * A single entry in the audit log.
 *
 * Each entry records an agent action with its context and result.
 * The entryHash provides integrity verification; when chained with
 * previousHash, entries form a tamper-evident log.
 */
export class AuditEntry {
  readonly action: string;
  readonly actor: string;
  readonly target: string;
  readonly result: string;
  readonly timestamp: Date;
  previousHash: string | null;
  readonly metadata: Record<string, string> | null;
  entryHash: string;

  constructor(init: AuditEntryInit) {
    this.action = init.action;
    this.actor = init.actor;
    this.target = init.target;
    this.result = init.result;
    this.timestamp = init.timestamp ?? new Date();
    this.previousHash = init.previousHash ?? null;
    this.metadata = init.metadata ?? null;
    this.entryHash = init.entryHash ?? "";

    if (!this.entryHash) {
      this.entryHash = this.computeHash();
    }
  }

  /** Compute SHA-256 hash of entry content. */
  computeHash(): string {
    const content = {
      action: this.action,
      actor: this.actor,
      target: this.target,
      result: this.result,
      timestamp: this.timestamp.toISOString(),
      previous_hash: this.previousHash,
      metadata: this.metadata,
    };
    const raw = JSON.stringify(content, Object.keys(content).sort());
    return createHash("sha256").update(raw, "utf-8").digest("hex");
  }

  /** Serialize to a dictionary (for JSON output). */
  toDict(): AuditEntryDict {
    const d: AuditEntryDict = {
      action: this.action,
      actor: this.actor,
      target: this.target,
      result: this.result,
      timestamp: this.timestamp.toISOString(),
      previous_hash: this.previousHash,
      entry_hash: this.entryHash,
    };
    if (this.metadata !== null) {
      d.metadata = this.metadata;
    }
    return d;
  }

  /** Deserialize from a dictionary. */
  static fromDict(data: AuditEntryDict): AuditEntry {
    return new AuditEntry({
      action: data.action,
      actor: data.actor,
      target: data.target,
      result: data.result,
      timestamp: new Date(data.timestamp),
      previousHash: data.previous_hash,
      metadata: data.metadata ?? null,
      entryHash: data.entry_hash,
    });
  }
}

/** Query filter options for AuditLog. */
export interface AuditQueryFilter {
  action?: string;
  actor?: string;
  result?: string;
  after?: Date;
  before?: Date;
}

/** Record options for AuditLog. */
export interface AuditRecordInit {
  action: string;
  actor: string;
  target: string;
  result: string;
  metadata?: Record<string, string>;
}

/**
 * Hash-chained, append-only audit log.
 *
 * Records agent actions with automatic hash chaining for
 * tamper detection. Supports JSONL file persistence and
 * querying by action, actor, result, and time range.
 */
export class AuditLog {
  private readonly _sessionId: string;
  private readonly _entries: AuditEntry[];

  constructor(sessionId: string) {
    this._sessionId = sessionId;
    this._entries = [];
  }

  /** Return the session identifier. */
  get sessionId(): string {
    return this._sessionId;
  }

  /** Return a read-only view of the entries list. */
  get entries(): readonly AuditEntry[] {
    return this._entries;
  }

  /**
   * Record a new audit entry.
   * The entry is automatically chained to the previous entry's hash.
   */
  record(init: AuditRecordInit): AuditEntry {
    const previousHash =
      this._entries.length > 0
        ? this._entries[this._entries.length - 1]!.entryHash
        : null;

    const entry = new AuditEntry({
      action: init.action,
      actor: init.actor,
      target: init.target,
      result: init.result,
      previousHash,
      metadata: init.metadata ?? null,
    });
    this._entries.push(entry);
    return entry;
  }

  /** Save the audit log to a JSONL file. */
  save(path: string): void {
    const lines = this._entries
      .map((entry) => JSON.stringify(entry.toDict()))
      .join("\n");
    writeFileSync(path, lines + "\n", "utf-8");
  }

  /** Load an audit log from a JSONL file. */
  static load(path: string, sessionId: string): AuditLog {
    if (!existsSync(path)) {
      throw new Error(`Audit log file not found: ${path}`);
    }
    const content = readFileSync(path, "utf-8");
    const log = new AuditLog(sessionId);
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const data = JSON.parse(trimmed) as AuditEntryDict;
      const entry = AuditEntry.fromDict(data);
      log._entries.push(entry);
    }
    return log;
  }

  /**
   * Verify the integrity of the hash chain.
   *
   * Checks that:
   * 1. Each entry's hash matches its content.
   * 2. Each entry's previous_hash matches the prior entry's hash.
   */
  verify(): boolean {
    for (let i = 0; i < this._entries.length; i++) {
      const entry = this._entries[i]!;

      // Verify the entry hash matches the content
      const expectedHash = entry.computeHash();
      if (entry.entryHash !== expectedHash) {
        return false;
      }

      // Verify the chain link
      if (i === 0) {
        if (entry.previousHash !== null) {
          return false;
        }
      } else {
        if (entry.previousHash !== this._entries[i - 1]!.entryHash) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Query audit entries with optional filters.
   * All filters are AND-combined.
   */
  query(filter: AuditQueryFilter): AuditEntry[] {
    const results: AuditEntry[] = [];
    for (const entry of this._entries) {
      if (filter.action !== undefined && entry.action !== filter.action)
        continue;
      if (filter.actor !== undefined && entry.actor !== filter.actor) continue;
      if (filter.result !== undefined && entry.result !== filter.result)
        continue;
      if (filter.after !== undefined && entry.timestamp <= filter.after)
        continue;
      if (filter.before !== undefined && entry.timestamp >= filter.before)
        continue;
      results.push(entry);
    }
    return results;
  }
}
