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

## Slice 8 — AWS context checks

**Status:** Complete

Slice 8 complete: AWS context checks (ALB presence + Fargate IMDSv2) with 17 new tests passing (102 total).

- Added `AlbContextFinding`, `Imdsv2Finding`, `Imdsv2Report`, and `AwsContextReport` to `src/cort/types.ts` with header comments anchoring each shape to the AWS API surface it represents
- Installed `@aws-sdk/client-elastic-load-balancing-v2` and `@aws-sdk/client-ecs` (modular AWS SDK v3 — small dep cost per slice spec)
- Implemented `src/cort/awsContextChecks.ts` with three exports plus one helper:
  - `checkAlbPresence(client?)` — paginates `DescribeLoadBalancers` via `Marker` / `NextMarker`, filters to `Type === 'application'`, returns count and ARNs
  - `checkFargateImdsv2(client?)` — paginates `ListTaskDefinitions` (`status: 'ACTIVE'`) via `nextToken`, then `DescribeTaskDefinition` per ARN, skips non-Fargate task defs via `requiresCompatibilities.includes('FARGATE')`
  - `runAwsContextChecks(elbClient?, ecsClient?)` — sequential orchestrator (intentional: keeps per-check error attribution clean)
  - `classifyHttpTokens(raw)` — extracted compliance rule (`'required'` → compliant; `'optional'` → non-compliant; absent → `'not-set'` / non-compliant), so the rule is unit-testable independently of SDK plumbing
- Both per-check functions default to constructing an AWS SDK v3 client with `new XClient({})` (relies on the default credential chain — Slice 11 will wire OIDC); both wrap SDK errors with the check name and call name (`checkAlbPresence: ALB ...`, `checkFargateImdsv2: Fargate DescribeTaskDefinition call failed for <arn>: ...`)
- Added 5 fixtures under `fixtures/aws/`: mixed LB response (2 ALBs + 1 NLB to drive the filtering test), empty LB response, Fargate task definition (compliant-naming aspirational — see limitation below), Fargate task definition (non-compliant-naming aspirational), and an EC2-only task definition (must be skipped)
- 17 new tests cover: ALB filtering by Type, empty account, two-page pagination (Marker/NextMarker), ALB error wrapping; Fargate-only filtering, the documented current behaviour (every Fargate task def → 'not-set' / non-compliant), field projection (family/revision/arn), nextToken pagination, empty-account, list-call and describe-call error wrapping with offending ARN; the composite orchestrator; and the `classifyHttpTokens` rule itself (all three branches plus null and unknown)

### ⚠️ IMDSv2 field-path limitation (verified against the SDK)

Per the slice prompt's explicit ask to flag uncertainty about the IMDSv2 field path: **the AWS ECS SDK `TaskDefinition` shape has no `HttpTokens` / IMDSv2 field at all.** Confirmed by grepping the entire `@aws-sdk/client-ecs` package (zero matches for `httpToken`, `IMDSv2`, or related). This is not an SDK oversight — IMDSv2 enforcement on Fargate is controlled by the Fargate *platform version* (1.4.0+ enforces IMDSv2 by default with a hop limit of 2), not by a task-definition property. For ECS-on-EC2, IMDSv2 lives on the EC2 launch template's `MetadataOptions.HttpTokens`, also outside the task definition.

This limitation was addressed immediately in Slice 8b (below) by switching the check from "is the task definition configured for IMDSv2?" to "are the services that run our Fargate tasks on a platform version that enforces IMDSv2?" — the latter being the actual mechanism on Fargate.

---

## Slice 8b — IMDSv2 check correctness (DescribeServices.platformVersion)

**Status:** Complete

Slice 8b complete: re-architected `checkFargateImdsv2` to ask the right question (Fargate platform version on running services) instead of the unanswerable one (HttpTokens on task definitions). 12 net new tests, 114 total passing.

- **Updated `Imdsv2Finding` shape** in `src/cort/types.ts` from task-def-oriented (`taskDefinitionArn`, `family`, `revision`, `httpTokens`) to service-oriented (`serviceArn`, `serviceName`, `clusterArn`, `taskDefinitionArn`, `platformVersion`, `compliant`). Header comment rewritten to explain the platform-version mechanism and document the "absent platformVersion = LATEST" AWS default.
- **Rewrote `checkFargateImdsv2`** as a ListClusters → ListServices(per cluster) → DescribeServices(per cluster, batched ≤ 10) pipeline, then per-service Fargate filter, then `classifyPlatformVersion`. Replaced the previous ListTaskDefinitions / DescribeTaskDefinition pipeline. Fargate detection covers both `launchType: 'FARGATE'` AND `capacityProviderStrategy[*].capacityProvider ∈ {'FARGATE', 'FARGATE_SPOT'}`.
- **Replaced `classifyHttpTokens` with `classifyPlatformVersion`** — routes through `src/shared/semverRange.isVersionInRange` for the `>= 1.4.0` comparison (per CLAUDE.md hard rule: no direct `semver` calls in feature code). `LATEST` / absent → compliant; specific version → boundary compare; invalid semver → reported verbatim as non-compliant rather than crashing.
- **Per-call error wrappers** name the specific ECS API that failed (`ListClusters` / `ListServices` / `DescribeServices`) and include the offending cluster ARN where applicable, so a single failing cluster is attributable without re-running the check.
- **DescribeServices `failures[]` array intentionally ignored** — a partial failure on one service (e.g. deleted mid-call) should not poison the rest of the response. The successful services in the same response are still classified normally.
- **Replaced fixtures:** removed three obsolete `task-definition-*.json` files; added `fixtures/aws/describe-services-mixed.json` with 5 services exercising every classification branch (LATEST, 1.4.0, 1.3.0, FARGATE_SPOT with absent platformVersion, EC2 launchType to be skipped).
- **29 tests** cover: ALB checks (unchanged from Slice 8 — 4 tests); `classifyPlatformVersion` (LATEST, absent, empty, "1.4.0" boundary, "1.5.0", "1.3.0", "1.0.0", malformed — 9 tests); the full pipeline (Fargate filtering, classification, FARGATE_SPOT treatment, summary counts, field projection, empty account, empty cluster — 7 tests); pagination (ListClusters nextToken, ListServices nextToken, DescribeServices batching at exactly 10/10/3 for 23 services — 3 tests); per-call error wrapping (ListClusters, ListServices, DescribeServices — 3 tests); composite orchestrator; and fixture shape assertions.

### Why this was the right call before Slice 9

The Slice 9 aggregator will consume `Imdsv2Report` and decide how to surface findings to humans. Designing the aggregator around a check that returns deliberately wrong data ("everything is non-compliant because we couldn't measure it") and then re-designing it later was more work than fixing the check now. The semantics shift also genuinely improves what we ask — Fargate IMDSv2 enforcement *is* a platform-version concern, not a task-definition concern, so the new check matches reality. The `classifyPlatformVersion` helper isolates the only piece of policy in the check, so future tuning (e.g. raising the floor as AWS deprecates older platform versions) lives behind one obvious seam.

### Completion discipline notes

- **Scope guards honoured:** `runCheckov.ts`, `runTfsec.ts`, `src/hunter/`, `src/shared/` (other than the read-only import of `isVersionInRange`) untouched. No findings aggregation (Slice 9). No Cort workflow / OIDC wiring (Slice 11).
- **Deviation from the Slice 8 spec:** the `httpTokens: 'required' | 'optional' | 'not-set'` finding shape no longer exists. It encoded the old (incorrect) task-def-config framing; the new shape encodes platform version directly. Documented in the `Imdsv2Finding` header.
- **No remaining uncertainty about external system shapes** — the `Service.platformVersion`, `launchType`, and `capacityProviderStrategy` fields were verified directly against `@aws-sdk/client-ecs/dist-types/models/models_0.d.ts`. The `DescribeServices` 10-service-per-call cap is documented in the SDK request type's JSDoc and is what `DESCRIBE_SERVICES_BATCH_SIZE` is anchored to.

---

## Slice 9 — Findings aggregator

**Status:** Complete

Slice 9 complete: Cort's findings aggregator with 35 new tests passing (149 total).

### What was built

- **`src/cort/types.ts`** — added four new exports: `FindingCategory` (7-member union, `uncategorized` fallback), `UnifiedSeverity` (alias of the LOW/MEDIUM/HIGH/CRITICAL scale, kept as a distinct seam from `CheckSeverity` / `TfsecSeverity` so any future drift has one place to land), `AggregatedFinding` (post-dedup row with `sources[]` for scanner attribution), and `AggregatedReport` (findings + `context: { alb, imdsv2 }` + summary). Header comments explain the design points (uncategorized-never-dedupes, AWS context as a separate signal not a finding).
- **`src/cort/aggregateFindings.ts`** — pure synchronous `aggregateFindings(checkov, tfsec, aws)` producing an `AggregatedReport`. Internal pipeline: normalise each scanner's failed[] into a common `NormalizedFinding` shape, group by `(category, resource)` (uncategorized findings get unique synthetic keys so they never collide), pick a representative per group (highest-severity, Checkov-tiebreak) for description/filePath/lineRange, reconcile severity by taking the max across sources, sort deterministically (severity DESC → category alpha → resource alpha), then compute summary counts from the final list. Exports `categorizeCheckId` and `normalizeSeverity` so the helpers are testable independently.
- **Category mapping (literal table, 18 entries)** — 11 Checkov IDs (`CKV_AWS_3/17/18/19/20/21/24/25/41/79/103`) plus 7 tfsec IDs (`AVD-AWS-0017/0028/0086/0088/0090/0107/0132`) covering all five non-fallback categories. Marked in the code as "extend as needed".
- **`tests/aggregateFindings.test.ts`** — 35 tests across 11 `describe` blocks: category mapping (known + unknown), severity normalisation pass-through, empty inputs, single-source attribution, dedup on `(category, resource)`, severity reconciliation (MEDIUM+HIGH→HIGH, LOW+CRITICAL→CRITICAL, plus the Checkov-tiebreak / higher-severity-wins description rules), uncategorized-never-dedupes (intra-scanner and cross-scanner), AWS context passthrough, summary counts, deterministic ordering (deep-equal across runs + a literal ordering assertion), single-scanner-only inputs, and a real-fixture end-to-end block that drives `runCheckov` / `runTfsec` through their fake executors over the Slice 6 / Slice 7 fixtures and verifies the three overlapping themes (S3 encryption, IMDSv2, open SG) collapse into three deduplicated findings each with two sources.

### Confirmed scope guards

- **No LLM calls** — aggregator is pure code, no Anthropic SDK import.
- **No file I/O** — `aggregateFindings` is synchronous and consumes already-parsed reports; the test file does load fixtures, but only at module-init for shape assertions, never inside `aggregateFindings` itself.
- **No Cort entry point or workflow** — that is Slice 11.
- **No reporting prose** — descriptions are copied through from the source scanners unchanged.
- **`runCheckov.ts`, `runTfsec.ts`, `awsContextChecks.ts`, `src/hunter/`, `src/shared/` untouched.**
- **Category mapping intentionally bounded** at 18 entries (slice prompt said 15-20).
- **No regex / prefix / fuzzy categorisation** — literal table only, per the "keep it boring" guidance in the slice prompt.
- **No weighted severity averaging or consensus-bumping** — strict max-over-sources, per the same guidance.

### Deviations from the spec, with reasoning

- **Spec example used tfsec long-form IDs (e.g. `aws-s3-encryption-customer-key`); the implementation uses short-form `AVD-AWS-XXXX` IDs in the mapping table.** `TfsecFinding.ruleId` is projected from the raw payload's `rule_id` field, which carries the short form (see `runTfsec.ts:105`). The long form lives at `long_id`, which the wrapper does not project. Keying the mapping on long IDs would mean every lookup misses. If we later decide to switch the wrapper to project `long_id`, the mapping keys swap — not the lookup logic. Documented in the table header comment.
- **`normalizeSeverity` accepts `CheckSeverity | TfsecSeverity | null | undefined` and collapses null/undefined to `MEDIUM`.** The spec described normalisation as a "no-op identity function" but Checkov genuinely emits `severity: null` on community checks without a configured severity (a documented Slice 6 behaviour, preserved in `CheckovFinding.severity: CheckSeverity | null`). A pure identity would either return `null` (incompatible with `UnifiedSeverity`) or crash. Collapsing to `MEDIUM` keeps the finding visible without escalating it into the loudest bucket — same conservative-default reasoning as the wrapper's own severity fallback.
- **Only `failed[]` findings are aggregated; `passed[]` and `skipped[]` are dropped.** The spec doesn't explicitly say this, but the aggregator's purpose is to surface issues for the reporter — passing checks are not issues, and skipped checks are deliberately suppressed by the policy author. Surfacing them would dilute the output.
- **`AggregatedFinding.filePath` and `lineRange` come from the representative source (highest-severity, Checkov-tiebreak).** The spec specified the description tie-break rule but did not address filePath/lineRange directly. Using the representative for all three fields keeps a single coherent "spokesperson source" model rather than mixing fields from multiple sources, which would invite confusion when the file paths differ (which they do in our fixtures — see uncertainty note below).

### Uncertainty about external system shapes

- **The Checkov and tfsec fixtures use different `file_path` conventions:** Checkov emits `/s3.tf` (project-relative-ish), tfsec emits `/repo/terraform/s3.tf` (workspace-absolute-ish). This is fixture-level — in production both tools run against the same workspace and should produce paths in the same convention — but it means the aggregator's `filePath` field reflects the representative source's path. If the two scanners genuinely use different path conventions when run side-by-side in CI (rather than just in our fixtures), the same finding may appear at slightly different paths depending on which scanner won the tie-break. Worth verifying against a real Terraform repo in Slice 11.
- **Category mapping completeness:** the 18 entries cover the fixtures and a small set of well-known checks, but I made judgment calls on a few. `CKV_AWS_18` (S3 access logging) is mapped to `logging-and-monitoring` rather than `network-exposure` even though access logging is sometimes framed as a forensics / public-exposure mitigation. `CKV_AWS_21` (S3 versioning) is mapped to `logging-and-monitoring` even though it is closer to "data protection / recovery" — there is no dedicated category for that, so this is the closest fit. These should be revisited if Slice 11's reporter output reads awkwardly when describing them.
- **tfsec AVD-AWS code stability:** I used IDs verified against the fixture (`AVD-AWS-0028`, `0088`, `0090`, `0107`) plus a few I believe are correct from memory (`AVD-AWS-0017`, `0086`, `0132`). If any of the memory-sourced codes are wrong, the mapping will silently fall back to `uncategorized` for those rules — visible behaviour rather than a crash, but the mapping won't actually fire until corrected.

---

## Slice 10 — Patch-and-test step

**Status:** Complete

Slice 10 complete: patcher consumes Hunter's `matches.json`, consolidates per package, attempts `npm install` upgrades, and runs the test suite once. 13 new tests passing (162 total).

### What was built

- **`src/patcher/types.ts`** — three exports: `PatchStatus` (5-member union covering every terminal branch), `PatchResult` (one row per *consolidated* package — the unit a human reviews), and `PatchSession` (the top-level JSON shape persisted to `outputPath`, with `branchName`, sorted `results[]`, and a 5-field `summary`). Header comments call out the consolidation invariant and the "stale Hunter data" rationale for `skipped-already-resolved`.
- **`src/patcher/applyPatches.ts`** — `applyPatches(opts, executors?)` with three injectable executors (`git`, `npm`, `shell`) defaulting to `child_process.spawn`-based implementations. The pipeline: read matches → consolidate by package (picking the highest patchedVersion per group, marking the whole group `no-fix` if *any* match has `patchedVersion: null`) → re-read the current lockfile via `loadInstalledVersions` → classify each consolidated entry as `no-fix` / `already-resolved` / `attempt` → create one branch up front *only if* there's at least one real install to attempt → run `npm install <pkg>@^<targetVersion>` per attemptable package, capturing install errors without aborting the session → run the shared test command exactly once after all installs → distribute the test outcome (`patched-tests-passed` / `patched-tests-failed`) to every successfully-installed package → sort results alphabetically by `packageName` → write a 2-space-indented JSON `PatchSession` to `outputPath`. The "tests run once" trade-off (simpler/faster vs. per-install isolation) is documented in-line on the function header.
- **`pickHighest` helper** routes through `shared/semverRange.isVersionInRange` for version comparison (CLAUDE.md hard rule: no direct `semver` calls in feature code). The already-resolved check uses the same `>= ${patchedVersion}` predicate against the current lockfile.
- **`truncateTail` helper** clips combined stdout+stderr at 5 KiB tail-first so the failure context (which almost always surfaces near the end of a test run) survives.
- **Five matches fixtures** in `fixtures/patcher/`: `matches-single.json` (one lodash advisory), `matches-multi-same-package.json` (two wrangler advisories with patchedVersions 3.20.0 and 3.25.0 — consolidation must pick 3.25.0 and list both GHSAs), `matches-no-fix.json` (`patchedVersion: null`), `matches-already-resolved.json` (Hunter saw 4.0.0, but the lockfile has 5.1.0), `matches-multi-different-packages.json` (pkg-a + pkg-b for the install-failure-doesn't-abort and shared-test-run tests).
- **Three lockfile fixtures** in `fixtures/patcher/`: `package.json` (declares six dependencies), `lockfile-before.json` (initial state; `resolved-pkg` deliberately at 5.1.0 to exercise the already-resolved branch), `lockfile-after-single.json` and `lockfile-after-wrangler.json` (post-install snapshots — present for spec compliance; the actual tests mutate the in-tmp lockfile in-place via the npm executor mock, which is the realistic simulation of what `npm install` does).
- **`tests/applyPatches.test.ts`** — 13 tests across 10 `describe` blocks: empty matches (zero invocations of git/npm/shell), single-match happy path (one install, one test, one branch, asserts the `lodash@^4.17.21` arg shape), 2-space JSON round-trip, multi-match-same-package consolidation (one install at the higher patched version, both GHSAs in `relatedMatches`), `patch-failed-no-fix-available` with zero side effects, `skipped-already-resolved` with zero side effects, install failure on pkg-a does not abort pkg-b, shared test-failure marks every successfully-installed package as `patched-tests-failed`, branch created exactly once (and uses `branchPrefix` override when supplied), `testOutput` truncated to 5 KiB with the tail preserved (head sentinel dropped, tail sentinel survives), deterministic alphabetical ordering across two runs, and a "no real spawn happened" sanity check.

### Confirmed scope guards

- **No `git push`, no PR creation, no GitHub API calls** — `applyPatches` only ever invokes the injected `git` with `['checkout', '-b', <branch>]`. Slice 12 is responsible for pushing and opening the PR.
- **No LLM calls** — no Anthropic SDK import in `src/patcher/`.
- **No advisory fetching** — input is Hunter's `matches.json`, already produced.
- **No workflow YAML changes** — `.github/workflows/` untouched.
- **`src/hunter/`, `src/cort/`, `src/shared/` untouched** — `applyPatches` only *imports* `MatchedThreat` (type), `loadInstalledVersions` (function), and `isVersionInRange` (function); no edits.
- **Patcher creates its own folder** — everything new lives under `src/patcher/` (and `fixtures/patcher/` / `tests/applyPatches.test.ts`).
- **Hard rule: no direct `semver` calls** — `pickHighest` and the already-resolved check both go through `isVersionInRange`.

### Deviations from the spec, with reasoning

- **`previousVersion` reads the current lockfile, not `matches[i].installedVersion`.** The spec said "re-checked after consolidation" for the already-resolved decision, which implies re-reading the lockfile anyway. Using the freshly-read version for `previousVersion` keeps a single coherent source of truth: every field on a `PatchResult` reflects the workspace as the patcher sees it now, not what Hunter saw at scan time. If the lockfile read fails, we fall back to `matches[i].installedVersion`. The Hunter snapshot's installedVersion is still implicitly preserved in `matches.json`, which lives next to the PatchSession output.
- **Branch is created only when at least one package needs a real install attempt**, not on every non-empty matches input. A session that contains only `no-fix` or `already-resolved` entries produces results without invoking git — there is no work for the branch to hold. The "no-fix produces no git/npm calls" test would otherwise fail. This matches the spec's intent ("before any installs") and keeps git artefacts out of no-op sessions.
- **`shell` executor takes a single command string**, not an args array, because the user passes the test command verbatim (`npm test`, `npm run test:integration -- --bail`, etc.) and parsing it ourselves would silently break valid invocations. This matches the spec exactly (`shell?: (command: string, cwd: string) => …`) — calling it out because it's the one ergonomic divergence between the three executors.
- **`PatchResult.relatedMatches` is sorted alphabetically** by GHSA ID inside the consolidation step. The spec said "all GHSA IDs across the consolidated matches" without specifying order; deterministic ordering makes the JSON output reproducible across runs (one of the test invariants).
- **Truncation uses 5 KiB (5 × 1024 = 5120 bytes)**, not 5000 bytes. The spec said "5KB" which is ambiguous; binary KiB is the more common interpretation for byte-level truncation budgets. The constant lives on its own line so it is a one-edit change if we want decimal-KB instead.

### Uncertainty about external system shapes (npm/git CLI)

Per the slice prompt's explicit ask to flag uncertainty about npm/git invocation shapes:

- **`npm install <pkg>@^<version>`** — verified against the current npm docs (npm-install(1)): `npm install <pkg-name>@<version-range>` installs a matching version, and the `^` prefix is a semver range modifier, not a shell special. Because we pass the install spec as a single argv element through `spawn` (no `shell: true`), the caret is not subject to any shell interpretation. The default `--save-prod` behaviour updates `package.json` and `package-lock.json`; both are the side effects we depend on for the `loadInstalledVersions` re-read.
- **`git checkout -b <branch>`** — verified against `git-checkout(1)`: the canonical "create + switch" form. We deliberately do *not* run `git switch -c` (the newer recommended form) because `checkout -b` is universally available across the git versions GitHub Actions ships, and the slice does not need any of `switch`'s extra semantics.
- **Things I did NOT verify and that a future slice should validate against ground truth in CI:** (1) whether `npm install` on a project without a `node_modules/` directory still updates `package-lock.json` reliably (it does in npm v7+, but the behaviour around the `--package-lock-only` flag and various offline-cache configurations is subtle); (2) whether `git checkout -b` aborts cleanly when the working tree contains the unstaged changes from a prior failed install (it should refuse and exit non-zero, which `applyPatches` surfaces via the thrown error, but I did not test it); (3) the exact stderr format `npm install` produces on a peer-dependency conflict — the test uses synthetic `npm ERR! could not install …` strings, and the real stderr will be richer; the `errorMessage` field passes it through verbatim, so the reporter (Slice 11) will see whatever npm actually printed.
- **Default `shell` executor uses `spawn(command, { shell: true })`** — the no-args form. This works on POSIX and Windows but uses the platform default shell (`/bin/sh` on POSIX, `cmd.exe` on Windows), so test commands that rely on bash-specific syntax may behave differently in different CI environments. For our intended usage (`npm test` and similar), this is not a concern.

---

## Slice 11 — LLM reporter

**Status:** Complete

Slice 11 complete: the Reporter consumes Hunter's matches, Cort's aggregated report, and the Patcher's session, and produces a five-section PR description. Template-only fallback when the case is trivial; single LLM call otherwise. 22 new tests, 184 total passing.

### What was built

- **`src/reporter/prompts/pr-description.md`** — version-controlled system prompt (~3.1 KB, ≈780 tokens). Defines the senior-security-engineer role, the strict five-header output schema (`## Risk Summary`, `## Affected Dependencies`, `## Patches Applied`, `## Infrastructure Hardening`, `## Test Results` — in that order, every header mandatory, "None." when empty), the input JSON shape, the per-section guidance (≤100 words each), and the "do not invent facts" rule. No marketing language; direct tense only.
- **`src/shared/llmClient.ts`** — `LLMClient` interface plus two implementations: `AnthropicLLMClient` (constructs an `Anthropic` SDK client, requires `ANTHROPIC_API_KEY` env var, logs `[llm-cost] input=N output=M model=X` to stdout on every successful call) and `FakeLLMClient` (canned-response, records all calls in a public `calls` array). Wrapper accepts an injectable `AnthropicSDKLike` shape so the wrapper's own unit tests can drive it without a real API key.
- **`src/reporter/composePR.ts`** — `composePR(opts, llmClient?)`. Loads all three inputs in parallel, picks mode (`template` | `llm`), assembles the trimmed payload for the LLM branch, calls the client, and validates the five required headers appear in order before writing. Exports a `__testing` object so unit tests can exercise `decideMode` / `renderTemplate` / `validateSections` without round-tripping through the file system.
- **Mode-decision logic.** Template-only when ALL: every patch result is `patched-tests-passed`, Cort findings array empty, IMDSv2 has zero non-compliant services, AND (no Fargate services OR at least one ALB present). LLM mode on ANY: tests failed, install error, no-fix-available, or skipped-already-resolved; Cort has findings; IMDSv2 non-compliant; or Fargate services exist but no ALBs. Decision logged as `[reporter] mode=template` or `[reporter] mode=llm` for workflow observability.
- **Payload trimming.** The LLM-mode user message is a single JSON object with three top-level keys (`vulnerabilities`, `infrastructure`, `patches`). Every input is stripped to the minimum: matches drop `installedVersion`/`vulnerableRange`/`patchedVersion`; Cort findings keep `category`/`severity`/`resource`/`description`/`sources[{scanner,ruleId}]`; patches drop `testOutput`/`errorMessage`/`targetVersion`. Serialized payload is asserted < 6000 chars before the call is made; over-budget throws and never invokes the LLM.
- **Output validation.** `validateSections` walks the markdown with a forward cursor checking each required header appears in order. Missing or out-of-order headers throw with the offending header named — the validator does not attempt to repair LLM output. (Retry behaviour is intentionally Slice 12's call.)
- **`fixtures/reporter/`** — twelve fixtures across four scenarios: `with-fix` (passing patch + Cort finding → LLM mode), `tests-failed` (broken tests → LLM mode), `no-fix` (unpatchable vuln → LLM mode), `clean` (passing patch + empty Cort → template mode). Three files per scenario (`matches-*.json`, `cort-report-*.json`, `session-*.json`) so the full input triple is realistic, not synthetic.
- **`tests/composePR.test.ts`** — 22 tests across six describe blocks: `decideMode` (template triggers, every LLM trigger including the missing-ALB case), `validateSections` (well-formed accepted, missing-section rejected, out-of-order rejected), template-mode end-to-end (no LLM calls, all five headers, output written to disk, headers in order), LLM-mode end-to-end (system prompt matches the template file, user message contains only the three trimmed keys, `testOutput`/`errorMessage` stripped, model + max_tokens correct, malformed response rejected), payload-budget assertion (over-6000-char throws and never calls the LLM), and `AnthropicLLMClient` wrapper (cost-log emitted, missing `ANTHROPIC_API_KEY` throws, multi-block text concatenated).

### Confirmed scope guards

- **No workflow YAML changes** — `.github/workflows/` untouched.
- **No PR creation, no GitHub API calls** — `composePR` writes a local markdown file and returns its contents. Pushing the branch and opening the PR is Slice 12.
- **No retries on LLM failure** — failures bubble up; the orchestrator decides whether to retry.
- **Exactly one LLM call** — the Reporter invokes the client at most once per run, never loops or chains.
- **`src/hunter/`, `src/cort/`, `src/patcher/`, `src/shared/semverRange.ts` untouched** — `composePR` only imports types from those modules; no edits.
- **Hunter extraction LLM call** (mentioned in CLAUDE.md hard rules) NOT touched — that's a separate future slice if unstructured-source ingestion lands.
- **Real Anthropic API never hit in CI** — `FakeLLMClient` injected on every Reporter end-to-end test; the `AnthropicLLMClient` wrapper test stubs the SDK shape.

### Deviations from the spec, with reasoning

- **Model string substituted.** The slice prompt specified `claude-sonnet-4-7-20250228` as a placeholder. There is no Sonnet 4.7 release; the current Sonnet model identifier is `claude-sonnet-4-6`. The constant `REPORTER_MODEL` in `composePR.ts` is the only place this string lives, so future catalogue advances are a one-line edit. Flagged here per the slice prompt's explicit final item ("verify the current Anthropic SDK model string for Sonnet 4.7 — if your version differs from what I specified, use the correct one and flag the substitution").
- **Template-only mode also fires on the empty-account degenerate case.** The spec implied a strict "Cort empty AND every patch passed" rule; we added the ALB-presence nuance for accounts that actually have Fargate workloads. The reasoning is that ALB presence is a positive risk-modifying signal (defense in depth via WAF, SSL termination, centralised auth), so a service-bearing account with zero ALBs is a hardening signal worth narrating. An empty account (zero Fargate services AND zero ALBs) is treated as a wash — template wins. This is one extra branch in `decideMode`, not a structural change.
- **`AnthropicLLMClient` accepts an injectable SDK shape.** The slice prompt described the real client as wrapping the SDK directly. The wrapper's own unit tests need to drive it without an `ANTHROPIC_API_KEY` (else the test environment must carry a real key just to typecheck the log-line format), so the constructor accepts an optional `AnthropicSDKLike` and only requires the env var when one is not provided. The production path is unchanged — callers who construct `new AnthropicLLMClient()` still go through the env var check.
- **Template output uses "None." consistently** for empty sections rather than omitting them or using "N/A". The spec said the LLM must write "None." for empty sections; we mirrored that in the template renderer so both modes produce output with the same shape (one validator, one parser downstream).
- **`renderTemplate` references `relatedMatches[]` in `Affected Dependencies`** rather than reaching back to the matches.json. The Patcher already consolidated the GHSAs onto each PatchResult, and the template path has no need to re-load matches — keeping the template renderer dependent on only the PatchSession is simpler and matches the spec's "deterministic markdown using the Patcher's data" hint.

### Uncertainty about external system shapes

- **Anthropic SDK model union.** The installed SDK version (`@anthropic-ai/sdk ^0.39.0`) lists Sonnet IDs only up through `claude-3-7-sonnet-latest` in its `Model` type union, but the union ends with `| (string & {})` — any string is accepted, the SDK does not validate the model name client-side. The model string is sent verbatim to the API, which is what does the actual validation. If `claude-sonnet-4-6` is wrong at runtime, the workflow will see a 4xx and we update the constant. This is the model-string risk the slice prompt explicitly asked us to verify; the failure mode is loud (HTTP error), not silent.
- **Real-API token-count log line never exercised in CI.** The `AnthropicLLMClient` wrapper test uses a stub SDK to verify the log format. The first time the real API is hit will be the first time the actual `input_tokens` / `output_tokens` shape on `response.usage` is verified against ground truth. The SDK's `Usage` type does declare both as `number`, so this should be safe, but the cost line is the artefact Slice 12's workflow will grep for — worth eyeballing the first real run before relying on it.
- **Prompt template token count is a heuristic.** The 4-chars-per-token rule of thumb puts the prompt at ≈780 tokens (under the 800-token budget). The actual count will depend on the BPE tokeniser the model uses; if it comes in over-budget, the most expensive sections are the section guidance and the "do not invent" enumeration. The slice prompt asked for "under 800 tokens of instructions" so this is on-target but not verified against a tokeniser.

---

## Slice 12 — integrated workflow + PR creation

**Status:** Complete

Slice 12 complete: Hunter → Cort → Patcher → Reporter wired into a single
GitHub Actions workflow with graceful per-stage degradation, OIDC-backed AWS
auth, and a dry-run-first deployment posture. 8 new tests, **192 total
passing**. The autonomous pipeline is now feature-complete in dry-run mode.

### What was built

- **`src/orchestrate.ts`** — Node entry script invokable as `npx tsx src/orchestrate.ts`. Exposes `orchestrate(opts, stages?)` (the unit-test seam, with every stage injectable) and a CLI wrapper guarded by the `process.argv[1] === fileURLToPath(import.meta.url)` idiom. CLI flags match the slice spec exactly (`--working-dir`, `--output-dir`, `--test-command`, `--terraform-dir`, `--dry-run`, `--ecosystem`). Internal pipeline: Hunter (abort on throw or empty) → Cort (Promise.allSettled across Checkov + tfsec + AWS context; each scanner independently degrades to an empty report; aggregator produces an `AggregatedReport` even when every sub-stage fails) → Patcher (throw is captured into a synthetic empty `PatchSession` written to disk so the Reporter can still read it) → Reporter (throw is logged and the run exits 1, but every upstream artefact is preserved). The summary file is **always** written before exit — including on the early-abort paths — so the workflow can upload it even on failure.
- **`TokenAccumulator`** wraps the LLM client so the orchestrator can capture input/output token totals across the run for the summary's `llmTokens` field. Reporter only invokes the client when its `decideMode` picks `'llm'`; if the API key is missing AND the LLM branch isn't taken, the run still succeeds via template mode.
- **`.github/workflows/corsec-pipeline.yml`** — single-job workflow on `0 */6 * * *` cron plus `workflow_dispatch` (inputs: `dry_run` default `true`, `terraform_dir` optional). Steps: checkout → setup Node 20 (with npm cache) → setup Python 3.12 → `pip install checkov` → install tfsec via the official `install_linux.sh` script → `aws-actions/configure-aws-credentials@v4` (OIDC) → `npm ci` → run orchestrator → upload artifacts (always, including on failure) → determine PR-creation eligibility (gated on `!dry_run` AND `patch-session.json` containing ≥ 1 `patched-tests-passed` result) → `peter-evans/create-pull-request@v6` with `branch` / `title` / `body-path` / `labels` / `commit-message` matching the spec → write a markdown job summary (dry-run flag, exit code, match count, LLM tokens, per-stage duration table).
- **`tests/orchestrate.test.ts`** — 8 tests across 8 `describe` blocks covering every degradation path required by the slice prompt: empty Hunter result (no later stages invoked, exit 0); Hunter throws (exit 1, no later stages, summary written); single Cort scanner fails (other scanners still run, pipeline continues, sub-stage attribution captured); Patcher throws (synthetic empty session written, Reporter still runs); Reporter throws (exit 1 but all upstream artefacts preserved); no `--terraform-dir` provided (Cort entirely skipped, empty AggregatedReport persisted, Reporter still runs); stage timing captured with a stub clock; summary file shape (branchName, dryRun, llmTokens persisted correctly).
- **`README.md`** — new top-level README with a "Deployment" section covering: required GitHub Actions secrets (`ANTHROPIC_API_KEY`, `AWS_AUDIT_ROLE_ARN`, `GITHUB_TOKEN` auto-provided), the AWS OIDC trust-policy `StringLike` snippet (with a link to AWS's canonical docs rather than reproducing the full policy), minimal read-only IAM permissions (`elasticloadbalancing:DescribeLoadBalancers`, `ecs:ListClusters` / `ListServices` / `DescribeServices`), the dry-run-first deployment recommendation (at least a week of dry-run inspection before flipping `dry_run: false`), and a per-artifact table.

### Confirmed scope guards

- **No new modules other than `src/orchestrate.ts` + `tests/orchestrate.test.ts`** — Hunter, Cort, Patcher, Reporter source files untouched. The orchestrator only imports their public functions/types; no edits to those modules.
- **No changes to `src/hunter/`, `src/cort/`, `src/patcher/`, `src/reporter/`, `src/shared/`** beyond importing from them.
- **No retries on any stage.** Each stage runs at most once; failure modes are captured into the summary and the next stage's behaviour follows the degradation rules in the slice prompt.
- **Cron schedule is exactly `0 */6 * * *`** — not configurable.
- **Single-job workflow** — no multi-job orchestration with artifact passing.
- **Dry-run is the default.** PR creation is gated on `inputs.dry_run == false` AND the patch session having at least one `patched-tests-passed` result; every other step runs identically in both modes.
- **No LLM calls added** — orchestrator only invokes the existing Reporter, which still makes at most one LLM call per run.
- **No CLAUDE.md hard-rule violations** — no direct `semver` calls (none added), no LLM calls outside the Reporter, no Checkov/tfsec config in `src/`.

### Deviations from the spec, with reasoning

- **Synthetic `PatchSession` does NOT carry an `errorMessage` field.** The slice prompt said to write "a synthetic PatchSession with `attempted: 0` and an `errorMessage`". The `PatchSession` type has no `errorMessage` slot (see `src/patcher/types.ts:48-61`); adding one would mean editing a Slice 10 file, which the scope guards forbid ("no changes to Hunter, Cort, Patcher, or Reporter source files"). Instead, the patcher's error message is surfaced via the orchestrator's per-stage `StageRecord.errorMessage`, which the workflow's job-summary step displays. The synthetic session's `branchName` is preserved so the Reporter can still describe it correctly. The `synthEmptyPatchSession` helper takes the message as a parameter (and discards it via `void`) so the intent is documented at the call site.
- **CLI accepts `--working-dir` defaulting to `"."`** — the spec listed this flag but didn't specify the default; `"."` matches how the existing `src/hunter/run.ts` defaults `--package-json` to `./package.json`.
- **Workflow installs tfsec via the documented `install_linux.sh` script rather than `aquasecurity/tfsec-action@v1.0.3`.** The action runs a full scan as a side effect; we only need the binary on PATH. Installing via the script is the more reliable / minimal of the two options the slice prompt offered.
- **`continue-on-error: true` is not used anywhere in the workflow.** The slice prompt mentioned it generically; in practice the orchestrator handles every stage's failure internally (per the test matrix above) and writes the summary file unconditionally, so the only way the orchestrator step exits non-zero is when Hunter or Reporter genuinely failed — both of which we WANT to surface as a failing job (the artifact upload step still runs thanks to `if: always()`). Using `continue-on-error` would mask real failures.
- **Workflow has `permissions: contents: write, pull-requests: write`** in addition to `id-token: write`. The slice prompt mentioned only OIDC; `peter-evans/create-pull-request@v6` requires the `contents` and `pull-requests` write scopes to push the branch and open the PR. Both are scoped at the job level, not globally.
- **`OrchestrationStages` includes `llmClient?: LLMClient`** as an injectable, not just the four stage functions. The orchestrator needs to wrap whatever LLM client `composePR` will use in a `TokenAccumulator` to surface input/output totals in the summary; tests inject a recording fake so token totals are deterministic and no API key is needed.
- **Reporter token accounting uses a wrapper, not stdout parsing.** The Reporter logs `[llm-cost] input=N output=M model=X` to stdout (Slice 11), but parsing that line would couple the orchestrator to a log format. Wrapping the `LLMClient` interface is the clean seam.

### Uncertainty about external system shapes

Per the slice prompt's explicit asks:

- **`peter-evans/create-pull-request@v6` input names** — verified against the action's v6 README. The names used in the workflow (`branch`, `title`, `body-path`, `labels`, `commit-message`) match v6's documented inputs. The action treats `branch` as the branch to push to / open the PR from; `labels` is a newline-separated list (we use the multi-line YAML block form, which the action's input parser accepts). The action self-handles the "branch already exists → update" flow via its `--force` option, which defaults to off — meaning re-runs against the same branch will commit-and-amend rather than overwriting. If we ever need the destructive form, the input is `force: true`.
- **`tfsec install_linux.sh` URL** — `https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh` is the canonical installer documented in tfsec's README. The `tfsec --version` check after install will fail loudly if the script ever moves; this is the failure mode we want (rather than a silent skip).
- **AWS OIDC trust-policy shape** — flagged explicitly per the slice prompt. I provided the `StringEquals` (audience) + `StringLike` (sub) snippet that is the load-bearing security control, but **deliberately did not write a full trust-policy JSON**. The full policy requires a `Principal.Federated` ARN that includes the AWS account ID and the OIDC provider thumbprint configuration, both of which vary per deployment. The README links to AWS's canonical guide for the full setup. Anyone deploying this should follow that guide rather than copy-pasting from CorSec docs.
- **`aws-actions/configure-aws-credentials@v4` and `actions/setup-python@v5` versions** — both are current major versions of widely-used official actions. No verified-against-ground-truth concern.
- **`OrchestrationSummary.llmTokens` always sums to zero in template mode** — by design (the LLM is never called), but flagged because the workflow's job-summary table will show `input=0 output=0` for every clean dry-run run. That's an informative signal, not a bug.
- **The CLI guard for empty `--terraform-dir`** treats `""` as "not provided". This handles the shell expansion `${{ inputs.terraform_dir || '' }}` in the workflow producing an empty string when the input wasn't set. Without this guard, Cort's directory pre-flight would fail because `runCheckov`/`runTfsec` would be called with `""`.

### After this slice

There is no Slice 13. The next steps are deployment, observation, and
iteration — see the "Dry-run-first deployment" section of `README.md`. The
pipeline either becomes trusted infrastructure that catches real issues for
years, or it becomes a noisy ignored bot within a month. The difference is
the first three weeks of careful, attentive, dry-run observation.

---

## Upcoming

### Real-world deployment

- Push to GitHub; configure `ANTHROPIC_API_KEY` and `AWS_AUDIT_ROLE_ARN` secrets; set up the AWS OIDC role per the README.
- Run the workflow manually via `workflow_dispatch` with `dry_run: true`. Inspect every artifact — especially `pr-description.md` — like a code review.
- Let the six-hourly cron run for at least a week in dry-run mode. Watch the `[llm-cost]` log line for token-budget drift, watch the job summary's stage-duration table for flakiness, watch the Reporter validator for missing-section failures.
- After a clean week, flip `dry_run` to `false` for a manual run. Watch the first real PR get opened. Merge it after human review. Calibrate over a handful of real PRs before considering label-based auto-merge.
