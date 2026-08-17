import type {
  AggregatedFinding,
  AggregatedReport,
  AwsContextReport,
  CheckSeverity,
  CheckovFinding,
  CheckovReport,
  FindingCategory,
  TfsecFinding,
  TfsecReport,
  TfsecSeverity,
  UnifiedSeverity,
} from './types.js';

// ─────────────────────────────────────────────────────────────────────────────
// Aggregator — merges Checkov + tfsec failed findings into a single
// deduplicated list and passes AWS context through unchanged. Pure synchronous
// transformation: no I/O, no LLM, no async. The reporter (Slice 11) is what
// turns this structured output into prose.
//
// Design choices worth flagging (and intentionally kept boring):
//
//   - Category mapping is a literal table keyed by check ID. We do NOT match
//     on regex / prefix / fuzzy keyword. A literal table is auditable, easy to
//     extend, and the explicit lookup means any unknown ID surfaces as
//     'uncategorized' rather than being silently miscategorised. If the table
//     ever grows past ~100 entries, a more sophisticated approach may pay for
//     itself — not before.
//
//   - Severity reconciliation is max-over-sources, full stop. No weighting,
//     no "if two scanners both say MEDIUM, bump to HIGH because consensus is
//     significant" — that is reporting nuance, not aggregation. Max is the
//     conservative, defensible default.
//
//   - Uncategorized findings never deduplicate, even when they share a
//     resource. The whole point of `uncategorized` is "we cannot prove these
//     are about the same underlying risk." Collapsing them on resource alone
//     would manufacture a confidence we do not have.
// ─────────────────────────────────────────────────────────────────────────────

// Severity ordering used for max-reconciliation and DESC sorting. Numeric ranks
// are an implementation detail — callers should never depend on the values.
const SEVERITY_RANK: Record<UnifiedSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

// Category mapping — extend as needed.
//
// Coverage is intentionally incomplete: roughly 15-20 well-known IDs per the
// slice scope, weighted toward checks that appear in our fixtures. Any rule ID
// not in this table maps to 'uncategorized' and surfaces as a finding without
// participating in dedup. That is correct behaviour, not a gap — see the
// uncategorized-never-dedupes rationale in the file header.
//
// Notes on ID forms:
//   - Checkov uses CKV_AWS_<n> (short, stable form). We key directly on it.
//   - tfsec has two ID forms — the short `AVD-AWS-XXXX` and the long
//     `aws-<service>-<slug>`. Our `TfsecFinding.ruleId` is projected from the
//     raw payload's `rule_id` field, which carries the SHORT form (the long
//     form lives at `long_id`). The table below therefore keys on AVD-AWS
//     codes. If we later switch the wrapper to project long IDs, swap the
//     keys here — not the lookup logic.
const CHECKOV_CATEGORIES: Record<string, FindingCategory> = {
  CKV_AWS_3: 'encryption-at-rest', // EBS volume encryption
  CKV_AWS_17: 'encryption-at-rest', // RDS storage encryption
  CKV_AWS_19: 'encryption-at-rest', // S3 server-side encryption
  CKV_AWS_18: 'logging-and-monitoring', // S3 access logging
  CKV_AWS_20: 'network-exposure', // S3 bucket ACL not public
  CKV_AWS_21: 'logging-and-monitoring', // S3 versioning
  CKV_AWS_24: 'network-exposure', // SG ingress from 0.0.0.0/0 to port 22
  CKV_AWS_25: 'network-exposure', // SG ingress from 0.0.0.0/0 to port 3389
  CKV_AWS_41: 'secrets-management', // AWS credentials in provider block
  CKV_AWS_79: 'identity-and-access', // EC2 IMDSv2 enforcement
  CKV_AWS_103: 'encryption-in-transit', // ELB TLS 1.2+
};

const TFSEC_CATEGORIES: Record<string, FindingCategory> = {
  'AVD-AWS-0017': 'logging-and-monitoring', // CloudTrail logging
  'AVD-AWS-0028': 'identity-and-access', // EC2 IMDSv2 enforcement
  'AVD-AWS-0086': 'network-exposure', // S3 no-public-buckets
  'AVD-AWS-0088': 'encryption-at-rest', // S3 bucket encryption
  'AVD-AWS-0090': 'logging-and-monitoring', // S3 versioning
  'AVD-AWS-0107': 'network-exposure', // SG no-public-ingress-sgr
  'AVD-AWS-0132': 'encryption-at-rest', // S3 encryption with customer key
};

export function categorizeCheckId(
  scanner: 'checkov' | 'tfsec',
  ruleId: string,
): FindingCategory {
  if (scanner === 'checkov') {
    return CHECKOV_CATEGORIES[ruleId] ?? 'uncategorized';
  }
  return TFSEC_CATEGORIES[ruleId] ?? 'uncategorized';
}

// No-op identity today since both scanners use the LOW/MEDIUM/HIGH/CRITICAL
// scale. Wrapped as a function so any future drift (a scanner adds INFO, or
// emits lowercase) has exactly one place to land.
//
// Checkov community checks emit severity: null; we collapse to MEDIUM as a
// conservative default rather than dropping the finding entirely. The
// aggregation layer needs a total ordering on severity, and null has no place
// in that ordering — picking MEDIUM keeps the finding visible without
// inappropriately escalating it. tfsec is non-null today, but the parameter
// accepts the same union for symmetry.
export function normalizeSeverity(
  _scanner: 'checkov' | 'tfsec',
  severity: CheckSeverity | TfsecSeverity | null | undefined,
): UnifiedSeverity {
  if (severity === 'LOW' || severity === 'MEDIUM' || severity === 'HIGH' || severity === 'CRITICAL') {
    return severity;
  }
  return 'MEDIUM';
}

function maxSeverity(a: UnifiedSeverity, b: UnifiedSeverity): UnifiedSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

// Internal pre-aggregation row — one per failed finding from either scanner,
// before grouping. Carries everything the dedup step needs.
interface NormalizedFinding {
  scanner: 'checkov' | 'tfsec';
  ruleId: string;
  category: FindingCategory;
  severity: UnifiedSeverity;
  resource: string;
  filePath: string;
  lineRange: [number, number];
  description: string;
}

function fromCheckov(f: CheckovFinding): NormalizedFinding {
  return {
    scanner: 'checkov',
    ruleId: f.checkId,
    category: categorizeCheckId('checkov', f.checkId),
    severity: normalizeSeverity('checkov', f.severity),
    resource: f.resource,
    filePath: f.filePath,
    lineRange: f.fileLineRange,
    description: f.checkName,
  };
}

function fromTfsec(f: TfsecFinding): NormalizedFinding {
  return {
    scanner: 'tfsec',
    ruleId: f.ruleId,
    category: categorizeCheckId('tfsec', f.ruleId),
    severity: normalizeSeverity('tfsec', f.severity),
    resource: f.resource,
    filePath: f.filePath,
    lineRange: f.lineRange,
    description: f.ruleDescription,
  };
}

// Pick the "spokesperson" source for a deduplicated group — its description,
// filePath, and lineRange become the AggregatedFinding's top-level fields.
// Rule: highest severity wins; ties broken by preferring Checkov, for stable
// ordering when both scanners flag the same thing at the same severity.
//
// This is an argmax, and that has a consequence worth stating: `best` is
// replaced only when candRank > bestRank (or on an equal-rank tie-break), so
// its rank is monotonically non-decreasing and on exit equals the group maximum.
// SEVERITY_RANK is injective, so `pickRepresentative(group).severity` IS
// max(group.severity) — which means the separate max-reconciliation loop in
// aggregateFindings provably recomputes a value already available here.
//
// That loop is kept deliberately. Collapsing it would save about five lines and
// turn a visible divergence (two independent computations that can be compared)
// into a silent dependency on this function's tie-break rule never changing —
// change the tie-break to prefer, say, the more detailed description, and the
// reported severity would follow it. The property test in
// tests/aggregateFindings.test.ts asserts the two agree.
function pickRepresentative(group: NormalizedFinding[]): NormalizedFinding {
  // Callers always pass a non-empty group (it is the value side of a Map that
  // was populated as findings were normalised). The `!` reflects that
  // construction-time invariant rather than runtime checks the caller already
  // proved.
  let best = group[0]!;
  for (let i = 1; i < group.length; i++) {
    const candidate = group[i]!;
    const candRank = SEVERITY_RANK[candidate.severity];
    const bestRank = SEVERITY_RANK[best.severity];
    if (candRank > bestRank) {
      best = candidate;
    } else if (candRank === bestRank && candidate.scanner === 'checkov' && best.scanner !== 'checkov') {
      best = candidate;
    }
  }
  return best;
}

function emptySeverityCounts(): Record<UnifiedSeverity, number> {
  return { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
}

function emptyCategoryCounts(): Record<FindingCategory, number> {
  return {
    'encryption-at-rest': 0,
    'encryption-in-transit': 0,
    'network-exposure': 0,
    'identity-and-access': 0,
    'logging-and-monitoring': 0,
    'secrets-management': 0,
    uncategorized: 0,
  };
}

export function aggregateFindings(
  checkov: CheckovReport,
  tfsec: TfsecReport,
  aws: AwsContextReport,
): AggregatedReport {
  // Only failed findings are aggregated. Passed and skipped checks are not
  // issues the reporter needs to surface; carrying them through would just
  // dilute the output.
  const normalized: NormalizedFinding[] = [
    ...checkov.failed.map(fromCheckov),
    ...tfsec.failed.map(fromTfsec),
  ];

  // Uncategorized findings never enter the dedup index at all — they go
  // straight into `groups` as singletons. Categorized findings additionally get
  // a (category, resource) entry in `byKey` so later findings can join them.
  //
  // This replaces a synthetic key of the form
  // `uncategorized::${i}::${scanner}::${ruleId}`, in which the entry index
  // alone already guaranteed uniqueness — so scanner and ruleId carried zero
  // uniqueness weight and were purely decorative. Worse, the key *read* as
  // "uncategorized dedupes on (scanner, ruleId)", the exact opposite of the
  // rule in force, so a maintainer tidying away the index-looking noise would
  // have silently collapsed findings on different resources.
  //
  // `groups` and `byKey` deliberately alias the same array objects: pushing
  // through a byKey lookup mutates the array already sitting in `groups`, which
  // is what preserves first-seen ordering.
  const groups: NormalizedFinding[][] = [];
  const byKey = new Map<string, NormalizedFinding[]>();
  for (const n of normalized) {
    if (n.category === 'uncategorized') {
      groups.push([n]);
      continue;
    }
    const key = `${n.category}::${n.resource}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.push(n);
    } else {
      const group = [n];
      groups.push(group);
      byKey.set(key, group);
    }
  }

  const findings: AggregatedFinding[] = [];
  for (const group of groups) {
    const representative = pickRepresentative(group);
    // group is non-empty: every entry in `groups` was created with a single
    // initial NormalizedFinding (the `groups.set(key, [n])` branch above).
    let severity: UnifiedSeverity = group[0]!.severity;
    for (let i = 1; i < group.length; i++) {
      severity = maxSeverity(severity, group[i]!.severity);
    }
    findings.push({
      category: representative.category,
      severity,
      resource: representative.resource,
      filePath: representative.filePath,
      lineRange: representative.lineRange,
      description: representative.description,
      sources: group.map((n) => ({
        scanner: n.scanner,
        ruleId: n.ruleId,
        originalSeverity: n.severity,
      })),
    });
  }

  // Deterministic ordering: severity DESC, then category alpha, then resource
  // alpha. Stable across runs — important because the reporter (and any
  // downstream consumer that diffs reports across builds) needs a reproducible
  // shape.
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    const catDiff = a.category.localeCompare(b.category);
    if (catDiff !== 0) return catDiff;
    return a.resource.localeCompare(b.resource);
  });

  // Summary counts are computed from the final aggregated list, not from the
  // raw inputs — so totalFindings reflects post-dedup count, not "Checkov
  // failed + tfsec failed".
  const bySeverity = emptySeverityCounts();
  const byCategory = emptyCategoryCounts();
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }

  return {
    findings,
    context: {
      alb: aws.alb,
      imdsv2: aws.imdsv2,
    },
    summary: {
      totalFindings: findings.length,
      bySeverity,
      byCategory,
    },
  };
}
