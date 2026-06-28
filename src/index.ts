/**
 * Git tool — typed interface for git operations.
 *
 * Wraps CommandRunner with git-specific operations and policy enforcement.
 * Used by:
 *   - `prx tools git exec` (CLI entry point, replaces scripts/git-safe)
 *   - Internal callers in src/pr-state/github.ts (direct function calls)
 */

import { processEnv } from "@bounded-systems/env";
import { captureFailureDetail, isCaptureFailure, spawnCapture } from "@bounded-systems/proc";
import {
  checkPolicy,
  isBlocked,
  type PolicyState,
  type PolicyRole,
  type PolicyDecision,
} from "@bounded-systems/policy";

import { runWithGitLockRecovery } from "./lock.ts";

export {
  recoverStaleLock,
  runWithGitLockRecovery,
  withGitLockRecovery,
  parseLockPath,
  isRetryableGitLock,
  DEFAULT_STALE_AGE_MS,
  type LockRecovery,
  type LockRecoveryDeps,
  type LockRecoveryHooks,
  type LockStat,
  type MinimalSpawnResult,
  type SpawnSeam,
} from "./lock.ts";

// Re-export the policy types that surface in this package's public API, so
// consumers depend on git's contract, not on @bounded-systems/policy directly
// (closes deno doc's `private-type-ref`).
export type { PolicyState, PolicyRole, PolicyDecision } from "@bounded-systems/policy";

/** The result of an {@link execGit} call: exit code, captured output, and the policy decision. */
export type GitExecResult = {
  /** The git process exit code. */
  exitCode: number;
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** The policy decision that gated the call, or `null` when policy wasn't enforced. */
  policy: PolicyDecision | null;
};

/** What to run and how to gate it for {@link execGit}. */
export type GitExecOptions = {
  /** The git subcommand (e.g. `status`, `commit`, `push`). */
  subcommand: string;
  /** Remaining git arguments. */
  args: string[];
  /** Working directory for the call. */
  cwd?: string | undefined;
  /** If set, enforce policy before executing. */
  state?: PolicyState | undefined;
  /** The actor role policy is evaluated against. */
  role?: PolicyRole | undefined;
};

/** Environment passed to the git child — recognized capability/role hints plus arbitrary passthrough. */
export type GitExecEnv = {
  /** Capability state hint read by the policy gate. */
  PRX_CAPABILITY_STATE?: string;
  /** Agent role hint read by the policy gate. */
  PRX_AGENT_ROLE?: string;
  /** Any other environment variables. */
  [key: string]: string | undefined;
};

const ALLOWED_SUBCOMMANDS = [
  "status",
  "diff",
  "log",
  "show",
  "rev-parse",
  "branch",
  "worktree",
  "fetch",
  "add",
  "commit",
  "restore",
  "switch",
  "checkout",
  "merge",
  "pull",
  "push",
  // GH-2381: object-graph materializers — gated to role=keeper by POLICY_TABLE.
  "write-tree",
  "commit-tree",
  // GH-201: local object export for the isolated keeper (keeperd). `bundle`
  // packs a commit range into a file so the host can ship objects to the in-VM
  // keeper, which imports them via `fetch` (already allowed) and does the signed
  // push. Read-only + local (no ref mutation, no network); gated to role=keeper.
  "bundle",
] as const;

/**
 * Execute a git subcommand with optional policy enforcement.
 */
export function execGit(opts: GitExecOptions, env: GitExecEnv = processEnv()): GitExecResult {
  // Hard-block check
  if (isBlocked("git", opts.subcommand)) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `git-safe: blocked subcommand '${opts.subcommand}'`,
      policy: null,
    };
  }

  // Allowlist check
  if (!(ALLOWED_SUBCOMMANDS as readonly string[]).includes(opts.subcommand)) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `git-safe: unknown or disallowed subcommand '${opts.subcommand}'`,
      policy: null,
    };
  }

  // Policy enforcement
  const state = opts.state ?? (env.PRX_CAPABILITY_STATE as PolicyState | undefined) ?? "validating";
  const role = opts.role ?? (env.PRX_AGENT_ROLE as PolicyRole | undefined) ?? "executor";
  const decision = checkPolicy("git", opts.subcommand, state, role);

  if (!decision.allowed) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `git-safe: blocked subcommand '${opts.subcommand}' for state '${state}' role '${role}'`,
      policy: decision,
    };
  }

  // Execute — GH-1609: stream stdout through spawnCapture so `git log -p`,
  // `git diff`, and similar large reads cannot hit the default 1 MiB stdout cap.
  // ai-home-bbdm1: a lock-contention failure (stale index.lock from a crashed
  // sibling) triggers a single safe-guarded stale-lock recovery + retry.
  // prx-e7cl / GH-388/GH-360: sign with OUR OWN key, headlessly — never the
  // operator's 1Password SSH agent (which hangs non-interactively: "agent
  // returned an error" → "failed to write commit object"). When
  // `PRX_COMMIT_SIGNING_KEY` names an ed25519 SSH *private key file* (not an
  // agent identity), every keeper/executor `commit`, `tag`, and `commit-tree` is
  // SSH-signed at creation, so commits land verified instead of being patched
  // after a branch-protection merge block. When it is unset we keep the
  // headless-safe default (signing disabled) so a misconfigured operator agent
  // can never hang a prx caller. The ed25519 provenance chain (anchored-chain)
  // remains the primary integrity layer; this is operator-layer defense in depth.
  const signingKeyFile = (env as Record<string, string>)["PRX_COMMIT_SIGNING_KEY"];
  const signs =
    opts.subcommand === "commit" ||
    opts.subcommand === "tag" ||
    opts.subcommand === "commit-tree";
  const signingConfig =
    signingKeyFile && signs
      ? [
          "-c",
          "gpg.format=ssh",
          "-c",
          `user.signingkey=${signingKeyFile}`,
          "-c",
          "commit.gpgsign=true",
          "-c",
          "tag.gpgsign=true",
        ]
      : opts.subcommand === "commit"
        ? ["-c", "commit.gpgsign=false"]
        : opts.subcommand === "tag"
          ? ["-c", "tag.gpgsign=false"]
          : [];
  // `git commit-tree` does not honor commit.gpgsign — it signs only with an
  // explicit `-S`. Inject it (it precedes the positional <tree>) when we sign.
  const commitTreeSign =
    signingKeyFile && opts.subcommand === "commit-tree" ? ["-S"] : [];
  const result = runWithGitLockRecovery(() =>
    spawnCapture(
      [
        "git",
        "-C",
        opts.cwd ?? process.cwd(),
        ...signingConfig,
        opts.subcommand,
        ...commitTreeSign,
        ...opts.args,
      ],
      { env: env as Record<string, string> },
    ),
  );

  if (isCaptureFailure(result)) {
    return {
      exitCode: result.status ?? 1,
      stdout: "",
      stderr: `git-safe: ${captureFailureDetail(result) || "git failed"}`,
      policy: decision,
    };
  }

  return {
    exitCode: 0,
    stdout: result.stdout,
    stderr: result.stderr,
    policy: decision,
  };
}

/** Render a {@link GitExecResult} as a one-line `plain` summary or pretty `json`. */
export function formatGitExecResult(result: GitExecResult, format: "plain" | "json"): string {
  if (format === "json") {
    return JSON.stringify(result, null, 2);
  }
  // Plain: just pass through stdout/stderr like native git
  let output = result.stdout;
  if (result.stderr && result.exitCode !== 0) {
    output = result.stderr;
  }
  return output.trimEnd();
}
