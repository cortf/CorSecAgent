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

export type CheckResult = 'PASSED' | 'FAILED' | 'SKIPPED';

// One row in Checkov's passed/failed/skipped arrays after normalisation.
// severity is nullable because Checkov assigns severity only when the policy
// has one configured (community checks frequently do not).
// guideline is nullable for the same reason — many checks have no remediation URL.
export interface CheckovFinding {
  checkId: string;
  checkName: string;
  result: CheckResult;
  severity: CheckSeverity | null;
  filePath: string;
  fileLineRange: [number, number];
  resource: string;
  guideline: string | null;
}

// Top-level report produced by `runCheckov`. The three arrays are partitioned
// by `result` and the summary counts mirror the array lengths exactly (the
// wrapper recomputes summary from the partitioned arrays rather than trusting
// Checkov's `summary` block, which also contains unrelated keys like
// parsing_errors and resource_count).
export interface CheckovReport {
  passed: CheckovFinding[];
  failed: CheckovFinding[];
  skipped: CheckovFinding[];
  summary: {
    passed: number;
    failed: number;
    skipped: number;
  };
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
// has no equivalent state, so carrying one would be dead weight. Summary
// counts mirror the partitioned array lengths exactly.
export interface TfsecReport {
  passed: TfsecFinding[];
  failed: TfsecFinding[];
  summary: {
    passed: number;
    failed: number;
  };
}
