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
