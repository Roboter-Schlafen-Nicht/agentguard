/**
 * Guard: the central policy enforcement point.
 *
 * The Guard class loads and manages policies, and evaluates agent actions
 * against all loaded policies. Main public API for the policy engine.
 *
 * @license AGPL-3.0-or-later
 */

import { loadPolicyFromFile, loadPolicyFromString } from "./loader.js";
import { evaluatePolicy, type Decision, type Policy } from "./models.js";

/**
 * Central policy enforcement point.
 *
 * A Guard manages a collection of policies and checks agent actions
 * against all of them. The first policy that denies an action wins.
 *
 * @example
 * ```ts
 * const guard = new Guard();
 * guard.addPolicy(myPolicy);
 * const result = guard.check("shell_command", { command: "rm -rf /" });
 * if (!result.allowed) {
 *   console.log(result.reason);
 * }
 * ```
 */
export class Guard {
  private readonly _policies: Policy[];

  constructor(policies?: readonly Policy[]) {
    this._policies = policies ? [...policies] : [];
  }

  /** Return the list of loaded policies. */
  get policies(): readonly Policy[] {
    return this._policies;
  }

  /** Add a policy to the guard. Returns self for chaining. */
  addPolicy(policy: Policy): this {
    this._policies.push(policy);
    return this;
  }

  /** Load a policy from a YAML string and add it. Returns self for chaining. */
  loadPolicyString(yamlStr: string): this {
    const policy = loadPolicyFromString(yamlStr);
    this._policies.push(policy);
    return this;
  }

  /** Load a policy from a YAML file and add it. Returns self for chaining. */
  loadPolicyFile(path: string): this {
    const policy = loadPolicyFromFile(path);
    this._policies.push(policy);
    return this;
  }

  /**
   * Check an action against all loaded policies.
   *
   * @param actionKind - The type of action (e.g. "shell_command").
   * @param params - Key-value parameters for the action.
   * @returns A Decision indicating whether the action is allowed or denied.
   */
  check(actionKind: string, params: Record<string, unknown> = {}): Decision {
    const action = { kind: actionKind, params };
    for (const policy of this._policies) {
      const decision = evaluatePolicy(policy, action);
      if (!decision.allowed) {
        return decision;
      }
    }
    return { allowed: true };
  }
}
