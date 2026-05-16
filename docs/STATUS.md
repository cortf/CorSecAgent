# Status

## Slice 1 — Scaffold

**Status:** Complete

Slice 1 complete: scaffold.

- Initialized `package.json` with TypeScript, tsx, vitest, @octokit/graphql, semver, @anthropic-ai/sdk
- Configured strict `tsconfig.json`
- Created folder structure: `src/{hunter,cort,reporter,shared}`, `policies/{checkov,custom}`, `fixtures`, `tests`, `docs`, `.github/workflows`
- Created `CLAUDE.md`, `.gitignore`, `vitest.config.ts`
- Renamed detection module from "Mitchell" → "Hunter" in CLAUDE.md hard rules (src/hunter/ was already correct)
- Confirmed zero references to "mitchell" or "frugal-agent" remain in repo

---

## Slice 2 — semverRange wrapper

**Status:** Complete

Slice 2 complete: semverRange wrapper with 35 tests passing.

- Implemented `src/shared/semverRange.ts` with `normalizeRange` and `isVersionInRange`
- `normalizeRange`: converts GitHub Advisory comma-separated ranges to semver-native space-separated form
- `isVersionInRange`: validates range (throws on invalid), returns false on invalid version strings, delegates to `semver.satisfies`
- Tests cover: simple ranges, compound ranges, wildcard, pre-release edge cases, invalid version strings (return false), invalid ranges (throw), and the real electerm advisory fixture (`>= 3.0.6, <= 3.8.8`)

---

## Upcoming

### Slice 3 — fetchAdvisories

Goal: GraphQL client for GitHub Advisory Database, returning typed Advisory[] for a given since-timestamp and ecosystem. Recorded fixture for tests, no live API in CI.
