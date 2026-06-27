import { test } from "bun:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertSeam } from "@bounded-systems/seam-check";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// @bounded-systems/git: the one allowed git subprocess point — policy-checked
// subcommands routed through the proc seam, with stale-lock recovery. Prod files
// touch the proc / policy / env / fs seams only. The harness proves that edge
// set and the no-ambient thesis.
test("@bounded-systems/git upholds its seam claim", () => {
  assertSeam({
    root: SRC,
    prod: [
      "@bounded-systems/proc",
      "@bounded-systems/policy",
      "@bounded-systems/env",
      "@bounded-systems/fs",
    ],
    test: ["@bounded-systems/git", "@bounded-systems/seam-check", "node:fs"],
  });
});
