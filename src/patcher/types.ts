// Per-package outcome after the patch attempt. The five states cover every
// terminal branch in applyPatches:
//
//   patched-tests-passed         — npm install succeeded AND the test suite
//                                  exited 0 (the test run is shared across all
//                                  successfully-installed packages this session)
//   patched-tests-failed         — npm install succeeded but the shared test
//                                  run exited non-zero; a human picks up here
//   patch-failed-install-error   — npm install exited non-zero; tests never run
//                                  for this package
//   patch-failed-no-fix-available — the advisory has no firstPatchedVersion;
//                                  no install attempted
//   skipped-already-resolved     — the current lockfile already has a version
//                                  >= patchedVersion (stale Hunter data, or a
//                                  prior session resolved this as a transitive)
//
// Declared as a const array with the union derived from it, so the runtime list
// and the type cannot drift. `emptyStatusCounts` in applyPatches.ts builds a
// Record keyed by this union, which makes adding a sixth status a compile error
// there rather than a silently missing summary bucket.
export const PATCH_STATUSES = [
  'patched-tests-passed',
  'patched-tests-failed',
  'patch-failed-install-error',
  'patch-failed-no-fix-available',
  'skipped-already-resolved',
] as const;

export type PatchStatus = (typeof PATCH_STATUSES)[number];

// One PatchResult per *consolidated* package. Multiple matches against the
// same package (e.g. two GHSAs both flagging wrangler) collapse into one
// install attempt and one PatchResult; relatedMatches preserves the GHSA IDs.
export interface PatchResult {
  packageName: string;
  // The installed version BEFORE the patch attempt (read from the current
  // lockfile, falling back to the matches.installedVersion if the lockfile
  // cannot be read).
  previousVersion: string;
  // null when the advisory has no firstPatchedVersion (no fix available).
  targetVersion: string | null;
  // null when the install was not attempted (no-fix, no-fix-available) or
  // when it failed before producing a lockfile entry.
  installedVersion: string | null;
  status: PatchStatus;
  // All GHSA IDs that this single patch attempt addresses, sorted.
  relatedMatches: string[];
  // Populated only when a step errored (install non-zero exit, etc.).
  errorMessage: string | null;
  // NOTE: no per-result testOutput. The suite runs ONCE per session and every
  // installed package shares its outcome, so storing the output per result
  // meant N byte-identical copies of one 5 KB string — and the type permitted
  // N *different* outputs, which the code can never produce. It lives on the
  // session as `testRun`.
}

export interface PatchSession {
  // Generated up front as `${branchPrefix}/${epochSeconds}`. The patcher does
  // NOT push this branch — that's a later slice's responsibility.
  branchName: string;
  // Sorted deterministically by packageName.
  results: PatchResult[];
  // The single shared test run. null when no install succeeded, so the suite
  // was never spawned. Every result whose status is `patched-tests-*` derives
  // that status from exactly this run.
  testRun: {
    status: 'passed' | 'failed';
    // Captured stdout+stderr, truncated to 5KB (tail kept — that's where
    // failures usually surface).
    output: string;
  } | null;
  summary: {
    // Every result produced, across all five statuses.
    total: number;
    // One bucket per status, always all five present. Replaces four ad-hoc
    // counters that between them covered only four of the five states:
    // `skipped-already-resolved` had no bucket yet was counted in the old
    // `attempted`, so `attempted !== succeeded + failedTests + failedInstall +
    // noFixAvailable` whenever an already-resolved package appeared. Two
    // hand-written artifacts in this repo disagreed about what `attempted`
    // meant, which is what made the ambiguity worth removing rather than
    // documenting.
    byStatus: Record<PatchStatus, number>;
  };
}
