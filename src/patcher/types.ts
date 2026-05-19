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
export type PatchStatus =
  | 'patched-tests-passed'
  | 'patched-tests-failed'
  | 'patch-failed-install-error'
  | 'patch-failed-no-fix-available'
  | 'skipped-already-resolved';

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
  // Captured stdout+stderr from the shared test run, truncated to 5KB (tail
  // kept — that's where failures usually surface). null for results where
  // tests never ran.
  testOutput: string | null;
  // Populated only when a step errored (install non-zero exit, etc.).
  errorMessage: string | null;
}

export interface PatchSession {
  // Generated up front as `${branchPrefix}/${epochSeconds}`. The patcher does
  // NOT push this branch — that's a later slice's responsibility.
  branchName: string;
  // Sorted deterministically by packageName.
  results: PatchResult[];
  summary: {
    attempted: number;
    succeeded: number;
    failedTests: number;
    failedInstall: number;
    noFixAvailable: number;
  };
}
