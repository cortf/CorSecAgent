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
