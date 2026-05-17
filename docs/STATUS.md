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

---

## Slice 3 — fetchAdvisories

**Status:** Complete

Slice 3 complete: GitHub Advisory GraphQL client with 7 tests passing (42 total).

- Created `src/hunter/types.ts` with `Advisory`, `Vulnerability`, `Ecosystem`, `Severity` interfaces grounded in the recorded fixture
- Implemented `fetchRecentAdvisories(sinceISO, ecosystem, client?)` in `src/hunter/fetchAdvisories.ts` using `@octokit/graphql`
- Queries `ghsaId`, `summary`, `severity`, `cvss { score }`, and `vulnerabilities(first: 10) { nodes { … } }` with `first: 100` advisories ordered by `publishedAt DESC`
- Optional third-argument client injection lets tests mock the graphql call without `GITHUB_TOKEN`; token is validated only when no client is provided
- Clear error thrown on missing `GITHUB_TOKEN` naming the variable and pointing to GitHub Actions secrets / local `.env`

---

---

## Slice 4 — matchDependencies

**Status:** Complete

Slice 4 complete: lockfile parsing and advisory matching with 15 new tests passing (57 total).

- Added `MatchedThreat` interface to `src/hunter/types.ts` — one record per installed package × matching vulnerable range
- Implemented `loadInstalledVersions(packageJsonPath, lockfilePath)` in `src/hunter/matchDependencies.ts`:
  - Reads both files in parallel via `fs/promises`
  - Resolves declared deps (union of `dependencies` + `devDependencies`) from the npm v7+ lockfile `packages` object
  - Transitive deps present in the lockfile but absent from `package.json` are excluded (planned for a later slice)
  - Throws clear errors naming the offending file path on missing file or malformed JSON
- Implemented `matchAdvisoriesAgainstDeps(advisories, installed)`:
  - Iterates every `vulnerabilities.nodes[]` entry — multi-node advisories produce one `MatchedThreat` per matching node
  - Version comparison routes through `isVersionInRange` (never `semver` directly)
  - Output is sorted deterministically by `ghsaId` then `packageName`
- Created `fixtures/lockfiles/` with five fixtures: clean pair (lodash, including a transitive dep for exclusion testing), vulnerable pair (wrangler@3.10.0), and a malformed JSON file for error-path tests
- Critical multi-node test verified: wrangler@3.10.0 produces exactly 2 matches (GHSA-cfph-4qqh-w828 + the `>= 3.0.0` node of GHSA-f8mp-x433-5wpf); wrangler@2.10.0 produces exactly 1 match (only the `>= 2.0.0, < 2.20.2` node of GHSA-f8mp-x433-5wpf)

---

---

## Slice 5 — Hunter entry point + first GitHub Actions workflow

**Status:** Complete

Slice 5 complete: end-to-end Hunter CLI + `workflow_dispatch` GitHub Actions workflow.

- Implemented `runHunter(opts, fetcher?)` in `src/hunter/run.ts` — fetches advisories, loads installed versions, matches, writes `MatchedThreat[]` JSON (2-space indent) to `outputPath`, returns `{ matchCount }`
- Advisory-fetcher injection follows the same optional-last-param pattern as `fetchRecentAdvisories`, keeping GITHUB_TOKEN and network I/O out of tests
- Thin CLI wrapper at the bottom of `run.ts` uses `node:util`'s `parseArgs`; required: `--output`; optional with sensible defaults: `--since` (24 h ago), `--ecosystem` (NPM), `--package-json` (./package.json), `--lockfile` (./package-lock.json)
- ESM direct-execution guard uses `process.argv[1] === fileURLToPath(import.meta.url)` so importing `runHunter` in tests never triggers CLI side effects
- Created `.github/workflows/hunter-scan.yml` with `workflow_dispatch` trigger: checkout → setup Node 20 + npm cache → `npm ci` → run Hunter → upload `hunter-matches.json` artifact → write match count to `$GITHUB_STEP_SUMMARY`
- 4 new tests in `tests/run.test.ts` covering: match count + written content (vulnerable fixture), JSON round-trip validity, deterministic sort order, and empty-array output (clean fixture)
- 61 total tests passing

---

## Slice 6 — Checkov wrapper

**Status:** Complete

Slice 6 complete: typed Checkov wrapper with 12 new tests passing (73 total).

- Added `src/cort/types.ts` with `CheckSeverity`, `CheckResult`, `CheckovFinding`, and `CheckovReport` — all grounded in Checkov's documented JSON output schema (https://www.checkov.io/8.Outputs/JSON.html) and normalised to camelCase / flatter shape than Checkov's raw payload
- Implemented `runCheckov(directory, executor?)` in `src/cort/runCheckov.ts`:
  - Exports `CheckovExecutor` so tests can inject a fake executor — the default executor is the only path that actually spawns `checkov`
  - Spawns with exactly `['-d', directory, '--framework', 'terraform', '--output', 'json', '--soft-fail']`
  - Pre-flights the directory via `fs.stat` so a missing path throws a clear error before the binary is invoked
  - Default executor intercepts `ENOENT` on spawn and rethrows with `pip install checkov` / `pipx install checkov` install hint
  - Throws clear errors for non-zero exit codes (naming exit code + stderr) and malformed stdout (naming the directory)
  - Recomputes `summary` from the partitioned arrays rather than trusting Checkov's `summary` block (which mixes in unrelated keys like `parsing_errors`)
- Added 3 fixtures under `fixtures/checkov/`: `clean-output.json` (2 passed, 0 failed), `findings-output.json` (mixed HIGH/CRITICAL/MEDIUM failures + 1 suppression), `malformed-output.json` (truncated JSON for error-path)
- 12 new tests cover: partitioning by result, summary counts, severity preservation, field projection from raw → CheckovFinding, exact executor args, malformed JSON, non-zero exit, missing directory (executor never called), and null severity on suppressed checks

---

## Upcoming

### Slice 7 — tfsec wrapper

Goal: tfsec wrapper following the same injectable-executor pattern as `runCheckov` — runs against a Terraform directory and returns typed findings.
