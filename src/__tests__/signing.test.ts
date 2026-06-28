// prx-e7cl — sign with OUR OWN key, headlessly. Integration proof: a real
// ed25519 SSH private-key FILE (no agent, no 1Password) configured via
// PRX_COMMIT_SIGNING_KEY makes the keeper's `commit-tree` produce an
// SSH-signed commit at creation; absent the key, signing stays off (the
// headless-safe default that can never hang a prx caller).

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { execGit } from "@bounded-systems/git";

let dir: string;
let keyFile: string;

/** Env that lets git/ssh-keygen run (PATH) without leaking the operator's vars. */
function baseEnv(): Record<string, string> {
  return {
    PATH: process.env["PATH"] ?? "/usr/bin:/bin",
    HOME: dir,
    GIT_AUTHOR_NAME: "keeper",
    GIT_AUTHOR_EMAIL: "keeper@prx.test",
    GIT_COMMITTER_NAME: "keeper",
    GIT_COMMITTER_EMAIL: "keeper@prx.test",
  };
}

const git = (args: string[]) => execFileSync("git", ["-C", dir, ...args]).toString();

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "prx-sign-"));
  keyFile = join(dir, "signing_key");
  // our own setup: a real ed25519 SSH key on disk — never 1Password
  execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "prx-keeper", "-f", keyFile]);
  git(["init", "-q"]);
  writeFileSync(join(dir, "f.txt"), "hello");
  git(["add", "f.txt"]);
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("execGit commit signing (prx-e7cl)", () => {
  test("commit-tree is SSH-signed with our own key when PRX_COMMIT_SIGNING_KEY is set", () => {
    const tree = git(["write-tree"]).trim();
    const res = execGit(
      { subcommand: "commit-tree", args: [tree, "-m", "signed"], cwd: dir, role: "keeper" },
      { ...baseEnv(), PRX_COMMIT_SIGNING_KEY: keyFile },
    );
    expect(res.exitCode).toBe(0);
    const obj = git(["cat-file", "commit", res.stdout.trim()]);
    // the commit object carries an inline SSH signature
    expect(obj).toContain("gpgsig");
    expect(obj).toContain("SSH SIGNATURE");
  });

  test("without PRX_COMMIT_SIGNING_KEY, commit-tree is unsigned (headless-safe default)", () => {
    const tree = git(["write-tree"]).trim();
    const res = execGit(
      { subcommand: "commit-tree", args: [tree, "-m", "unsigned"], cwd: dir, role: "keeper" },
      baseEnv(),
    );
    expect(res.exitCode).toBe(0);
    expect(git(["cat-file", "commit", res.stdout.trim()])).not.toContain("gpgsig");
  });
});
