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

## Slice 7 — tfsec wrapper

**Status:** Complete

Slice 7 complete: typed tfsec wrapper with 12 new tests passing (85 total).

- Extended `src/cort/types.ts` with `TfsecSeverity` (aliased to `CheckSeverity` since the two scales align today, kept as a distinct export so future drift has a single seam), `TfsecFinding` (flatter, camelCased — projects `location.filename` / `start_line` / `end_line` into `filePath` + `lineRange`), and `TfsecReport` — no `skipped` array, since tfsec has no equivalent state (commented in the type header)
- Implemented `runTfsec(directory, executor?)` in `src/cort/runTfsec.ts`:
  - Exports `TfsecExecutor` so tests can inject a fake executor — the default executor is the only path that actually spawns `tfsec`
  - Spawns with exactly `[directory, '--format', 'json', '--soft-fail']` — directory is the positional arg, NOT behind a `-d` flag (the real behavioural difference from Checkov)
  - Pre-flights the directory via `fs.stat` so a missing path throws a clear error before the binary is invoked
  - Default executor intercepts `ENOENT` on spawn and rethrows with a pointer to https://github.com/aquasecurity/tfsec (install varies by platform — brew / `go install` / binary / container — so no single command is prescribed)
  - Normalises `status` from tfsec's integer enum (0 = failed, 1 = passed, 2 = ignored per `pkg/scan/result.go`) into the narrowed `'passed' | 'failed'` form; also accepts the string form defensively
  - Throws clear errors for non-zero exit codes (naming exit code + stderr) and malformed stdout (naming the directory)
  - Recomputes `summary` from the partitioned arrays rather than trusting any tfsec-level summary
- Added 3 fixtures under `fixtures/tfsec/`: `clean-output.json` (2 passed, 0 failed), `findings-output.json` (IMDSv2 HIGH + S3-encryption CRITICAL + open-SG MEDIUM failures plus 1 passing S3-versioning check — themes deliberately overlap the Checkov findings fixture so Slice 9's aggregator has real dedup material), `malformed-output.json` (truncated JSON for error-path)
- 12 new tests cover: empty `results[]` produces empty arrays + zero counts, partitioning by `status`, summary counts, severity preservation, field projection (location → filePath/lineRange, resolution surfaced), exact executor args **with explicit assertion that `-d` is absent and the directory sits at position 0**, malformed JSON, non-zero exit, and missing-directory short-circuit (executor never called)

### Non-trivial differences from `runCheckov` (notes for the future refactor)

- **CLI shape:** Checkov takes `-d <dir>`; tfsec takes `<dir>` positionally. A shared executor abstraction would need a per-tool args builder, not a shared arg list.
- **Output partitioning:** Checkov pre-partitions into `passed_checks` / `failed_checks` / `skipped_checks`; tfsec emits one flat `results[]` and the wrapper partitions on a `status` field. A shared finding-mapper would need to plug in different "split this raw payload into buckets" strategies.
- **Status encoding:** tfsec uses an integer enum (0/1/2); Checkov uses uppercase result strings. Both wrappers ended up with their own `normaliseStatus`/`normaliseResult` function.
- **Severity nullability:** Checkov frequently emits `severity: null` on community checks → `CheckSeverity | null`; tfsec always ships a severity → `TfsecSeverity` (non-null). The shared finding type can't simply union these without losing precision.
- **Skipped state:** Checkov has a third bucket; tfsec doesn't. A shared report type either carries an always-empty `skipped` for tfsec or is generic over the bucket set. The current per-tool types sidestep this.
- **Install-hint copy:** Checkov has one canonical install (`pip install checkov`); tfsec installs vary by platform. The shared default-executor builder would need a per-tool error-hint string.
- **Location shape:** Checkov sets `file_path` + `file_line_range` as siblings; tfsec nests them under `location`. The raw-shape parsers differ structurally, not just by key name.

Net assessment: ~70% of the wrapper bodies overlap structurally (pre-flight → spawn → exit-code check → JSON parse → partition → summary → throw shapes), but every meaningful seam (args, partition predicate, status normaliser, severity nullability, install hint, raw → finding mapper) varies by tool. A shared `runScanner` would need 6+ injection points, which is roughly the same surface area as keeping two concrete wrappers. Worth revisiting only if a third scanner lands.

---

## Upcoming

### Slice 8 — AWS context checks

Goal: AWS context checks (ALB presence, IMDSv2 enforcement on Fargate task definitions) via injectable AWS SDK clients — same dependency-injection pattern as the scanner wrappers.
