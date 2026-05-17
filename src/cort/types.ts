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
