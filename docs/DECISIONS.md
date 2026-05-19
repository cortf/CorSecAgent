# Architectural Decisions

## ADR-001 — Module Bundler: None (native ESM)

**Date:** 2026-05-15
**Status:** Accepted

Node 22+ with `"type": "module"` and `tsx` for development removes the need for a bundler. `tsc` handles production builds.

---

## ADR-002 — Test Runner: Vitest

**Date:** 2026-05-15
**Status:** Accepted

Vitest provides Jest-compatible APIs with native ESM and TypeScript support without additional transforms.

---

<!-- Add new ADRs above this line -->

2026-05-16: Advisory.cvss is nullable because GitHub's API can omit it. Reporter must handle null gracefully — likely fall back to severity (LOW/MODERATE/HIGH/CRITICAL) as the urgency signal when CVSS is absent.

2026-05-17: Slice 7 surfaced 6 structural seams between runCheckov and runTfsec. Considered extracting a shared runScanner primitive. Decided against: a shared abstraction would parameterize the differences rather than hide them, requiring ~6 injection points and roughly equal surface area to two concrete wrappers. Revisit only if a third scanner lands and the variance pattern becomes clear.

2026-05-17: tfsec rule IDs are short-form (AVD codes or short slugs), not long-form descriptions. The category mapping in aggregateFindings.ts keys off the short form to match what tfsec actually emits.

2026-05-17: CKV_AWS_21 (S3 versioning) categorized as logging-and-monitoring provisionally. Versioning is conceptually closer to data-protection / recoverability but no such category exists yet. Revisit after Slice 11 shows whether the reporter's prose feels awkward.

2026-05-17: Patcher reads previousVersion from the live lockfile rather than matches[i].installedVersion. The matches file is a point-in-time artifact; the lockfile is ground truth at patch-time.

2026-05-17: Local-mode patching (running applyPatches outside the CI workflow) assumes a clean working tree. `git checkout -b` will carry unstaged changes from a prior failed install onto the new branch. CI runners start from a fresh checkout so this is a non-issue in the workflow path. If local-mode usage grows, gate branch creation behind a `git status --porcelain` check or a `git stash` step.

2026-05-17: Peer-dependency conflict stderr shape from `npm install` is the highest-risk unverified surface in Slice 10. The patcher passes npm's stderr through verbatim in `PatchResult.errorMessage`, so the Slice 11 reporter is what sees the real format. Action for Slice 11: construct a fixture that triggers a real peer-dep conflict (e.g., installing a package requiring React 19 against a React-18-pinned project) and capture the actual stderr as the reporter's error-narration test fixture.
