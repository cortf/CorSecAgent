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

## Upcoming

### Slice 9 — Findings aggregator

Goal: aggregator that consumes Checkov + tfsec + AWS context reports and produces a unified deduplicated findings structure.
