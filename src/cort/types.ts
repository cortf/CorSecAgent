// Types for Checkov scan results.
//
// Field names and shapes are grounded in Checkov's documented JSON output:
// https://www.checkov.io/8.Outputs/JSON.html
//
// Checkov's raw output uses snake_case (check_id, file_line_range, etc.) and
// nests the result string under `check_result.result`. The shapes below are the
// *normalised* CorSecAgent representation produced by `runCheckov` — flatter
// and camelCased — not the raw Checkov payload.

export type CheckSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// One row in Checkov's passed/failed/skipped arrays after normalisation.
// severity is nullable because Checkov assigns severity only when the policy
// has one configured (community checks frequently do not).
// guideline is nullable for the same reason — many checks have no remediation URL.
//
// Deliberately carries no `result` field. Checkov's payload is already
// partitioned into passed/failed/skipped arrays, and `runCheckov` projects all
// three identically — so a per-row result string could only ever restate, or
// contradict, the array the row already sits in. Array membership is the single
// source of truth.
export interface CheckovFinding {
  checkId: string;
  checkName: string;
  severity: CheckSeverity | null;
  filePath: string;
  fileLineRange: [number, number];
  resource: string;
  guideline: string | null;
}

// Top-level report produced by `runCheckov`. No summary block: the counts it
// used to carry were exactly the three array lengths, stored beside the arrays
// and hand-maintained by every test literal that built a report. Callers that
// want a count read `.failed.length`.
export interface CheckovReport {
  passed: CheckovFinding[];
  failed: CheckovFinding[];
  skipped: CheckovFinding[];
}

// ─────────────────────────────────────────────────────────────────────────────
// tfsec types
//
// Field names and shapes are grounded in tfsec's documented JSON output.
// Reference: https://github.com/aquasecurity/tfsec (the `Result` struct in
// pkg/scan and the JSON formatter under internal/pkg/formatters/json).
//
// tfsec's JSON shape differs from Checkov's in three notable ways:
//
//   1. It is flatter — a single top-level `results` array, with each entry
//      carrying its own `status` field rather than being pre-partitioned into
//      passed/failed/skipped arrays. The wrapper does the partitioning.
//   2. There is no equivalent of Checkov's "skipped" state. tfsec either emits
//      a result or it doesn't — so `TfsecReport` deliberately has no `skipped`
//      field (rather than carrying an always-empty array).
//   3. Location is nested under `location: { filename, start_line, end_line }`
//      rather than living as a sibling `file_path` + `file_line_range`.
// ─────────────────────────────────────────────────────────────────────────────

// tfsec uses the same four-level severity scale as Checkov today, so this is
// aliased to avoid drift. Kept as a distinct exported name because the two
// tools are conceptually independent — if either ever adds INFO / UNKNOWN /
// etc., the alias is the single point where they would split.
export type TfsecSeverity = CheckSeverity;

// One row in tfsec's results array after normalisation. `status` is narrowed
// to 'passed' | 'failed' — tfsec has no "skipped" concept (see header note).
// `resolution` is nullable because while tfsec generally ships a remediation
// string per rule, we keep it permissive in case a custom rule omits one.
export interface TfsecFinding {
  ruleId: string;
  ruleDescription: string;
  severity: TfsecSeverity;
  status: 'passed' | 'failed';
  filePath: string;
  lineRange: [number, number];
  resource: string;
  resolution: string | null;
}

// Top-level report produced by `runTfsec`. Note: no `skipped` array — tfsec
// has no equivalent state, so carrying one would be dead weight. Also no
// summary block, for the same reason as CheckovReport: it restated the two
// array lengths.
//
// Unlike Checkov's, `TfsecFinding.status` is retained — it is the partition
// predicate itself, computed once from tfsec's raw integer enum and then used
// to split `results[]`, so it cannot disagree with array membership by
// construction.
export interface TfsecReport {
  passed: TfsecFinding[];
  failed: TfsecFinding[];
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS context check types
//
// Where Checkov and tfsec inspect IaC at rest, the AWS context checks inspect
// what is *actually deployed* in the account by querying live AWS APIs. The
// reports below are produced by `runAwsContextChecks` and the per-check
// helpers in src/cort/awsContextChecks.ts.
// ─────────────────────────────────────────────────────────────────────────────

// Result of `checkAlbPresence`. Account-level presence only for this slice —
// a future slice may refine this to "is THIS service behind an ALB" by joining
// against target group / listener data.
export interface AlbContextFinding {
  albCount: number;
  albArns: string[];
}

// One row per Fargate-running ECS service inspected by `checkFargateImdsv2`.
//
// This check answers "are the services that run our Fargate task definitions
// on a Fargate platform version that enforces IMDSv2?" — rather than asking
// the task definition directly, because the AWS ECS SDK does not expose any
// HttpTokens / IMDSv2 field on the TaskDefinition shape. IMDSv2 enforcement
// on Fargate is controlled by the *platform version*: 1.4.0+ enforces IMDSv2
// by default with a hop limit of 2 (released April 2020). `LATEST` is always
// the current platform version and is therefore always compliant.
//
// "Compliant" therefore means the service's platformVersion is `LATEST` or a
// specific version `>= 1.4.0`. Anything earlier (`1.3.0`, `1.0.0`, …) is
// flagged. A service with no explicit platformVersion defaults to `LATEST`
// per the AWS docs (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html),
// so the wrapper normalises absent values to `'LATEST'` rather than treating
// them as a missing-data finding.
//
// Only services running on Fargate are inspected — EC2-launch services are
// skipped entirely. Fargate detection covers both `launchType: 'FARGATE'` and
// capacity-provider services using `'FARGATE'` or `'FARGATE_SPOT'`.
export interface Imdsv2Finding {
  serviceArn: string;
  serviceName: string;
  clusterArn: string;
  taskDefinitionArn: string;
  platformVersion: string;
  compliant: boolean;
}

// Top-level report produced by `checkFargateImdsv2`. Summary counts mirror
// the partitioned counts on `checked` exactly.
export interface Imdsv2Report {
  checked: Imdsv2Finding[];
  compliantCount: number;
  nonCompliantCount: number;
}

// Composite report produced by `runAwsContextChecks` — the two per-check
// reports rolled into one object so downstream consumers (the future Slice 9
// aggregator) only have to depend on a single top-level type.
export interface AwsContextReport {
  alb: AlbContextFinding;
  imdsv2: Imdsv2Report;
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregator types (Slice 9)
//
// The aggregator merges Checkov + tfsec failed findings into a single
// deduplicated list, and passes the AWS context report through as a separate
// "context" field. The shapes below are the *output* of `aggregateFindings`
// in src/cort/aggregateFindings.ts and the input shape the reporter (Slice 11)
// will consume.
// ─────────────────────────────────────────────────────────────────────────────

// Stable categories used to deduplicate findings across scanners. The category
// for a given check ID is looked up in a literal table in aggregateFindings.ts.
// Unknown check IDs collapse to 'uncategorized', which is treated specially by
// the deduplicator — uncategorized findings never deduplicate (even when they
// share a resource) because we cannot prove two unknown IDs describe the same
// underlying risk.
export type FindingCategory =
  | 'encryption-at-rest'
  | 'encryption-in-transit'
  | 'network-exposure'
  | 'identity-and-access'
  | 'logging-and-monitoring'
  | 'secrets-management'
  | 'uncategorized';

// Unified severity scale used after normalisation. Both Checkov and tfsec
// currently emit this exact set, so normalisation is the identity function
// today — the type exists so that any future drift (a scanner adds INFO /
// UNKNOWN) has a single, central seam to handle it.
export type UnifiedSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// A single finding after merge + dedup. When two scanners flag the same
// (category, resource) tuple, their attributions are folded into the `sources`
// array on a single AggregatedFinding rather than appearing as two separate
// rows. Source attribution is preserved so the reporter can cite which
// scanner(s) flagged a given issue.
//
// `severity` is the reconciled max across all sources. `description`,
// `filePath`, and `lineRange` are taken from the highest-severity source
// (tie-break: prefer Checkov, for stable ordering when both scanners report
// the same severity).
export interface AggregatedFinding {
  category: FindingCategory;
  severity: UnifiedSeverity;
  resource: string;
  filePath: string;
  lineRange: [number, number];
  description: string;
  sources: Array<{
    scanner: 'checkov' | 'tfsec';
    ruleId: string;
    originalSeverity: UnifiedSeverity;
  }>;
}

// Top-level report produced by `aggregateFindings`. The `context` block carries
// the AWS context report through unchanged — it is intentionally NOT folded
// into `findings` because ALB presence and IMDSv2 platform-version state are
// risk-modifying signals about the deployed environment, not finding-level
// issues in their own right.
export interface AggregatedReport {
  findings: AggregatedFinding[];
  context: {
    alb: AlbContextFinding;
    imdsv2: Imdsv2Report;
  };
  summary: {
    totalFindings: number;
    bySeverity: Record<UnifiedSeverity, number>;
    byCategory: Record<FindingCategory, number>;
  };
}
