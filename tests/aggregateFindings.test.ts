import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  aggregateFindings,
  categorizeCheckId,
  normalizeSeverity,
} from '../src/cort/aggregateFindings.js';
import { runCheckov, type CheckovExecutor } from '../src/cort/runCheckov.js';
import { runTfsec, type TfsecExecutor } from '../src/cort/runTfsec.js';
import type { CheckovFinding, TfsecFinding } from '../src/cort/types.js';
import {
  emptyAwsContextReport,
  emptyCheckovReport,
  emptyTfsecReport,
} from './helpers/emptyReports.js';

// ─────────────────────────────────────────────────────────────────────────────
// Fixture loading. We reuse the shared findings fixtures used by Slice 6 and
// Slice 7, since their themes (S3 encryption, IMDSv2, open SG) overlap by
// design — they exist precisely to give the aggregator real dedup material.
// ─────────────────────────────────────────────────────────────────────────────

const checkovFindingsStdout = readFileSync(
  new URL('../fixtures/checkov/findings-output.json', import.meta.url),
  'utf-8',
);
const tfsecFindingsStdout = readFileSync(
  new URL('../fixtures/tfsec/findings-output.json', import.meta.url),
  'utf-8',
);

const here = dirname(fileURLToPath(import.meta.url));
const CHECKOV_FIXTURE_DIR = resolve(here, '../fixtures/checkov');
const TFSEC_FIXTURE_DIR = resolve(here, '../fixtures/tfsec');

function makeCheckovExecutor(stdout: string): CheckovExecutor {
  return vi.fn().mockResolvedValue({ stdout, stderr: '', exitCode: 0 });
}

function makeTfsecExecutor(stdout: string): TfsecExecutor {
  return vi.fn().mockResolvedValue({ stdout, stderr: '', exitCode: 0 });
}

// Aliased to the suite-wide name. The local copy this replaced still carried
// albCount / compliantCount / nonCompliantCount long after those fields were
// removed — it typechecked only because tsconfig excludes tests/, which is the
// rot a shared builder prevents.
const emptyAwsContext = emptyAwsContextReport;

function checkovFinding(over: Partial<CheckovFinding> = {}): CheckovFinding {
  return {
    checkId: 'CKV_AWS_19',
    checkName: 'Ensure all data stored in the S3 bucket is securely encrypted at rest',
    severity: 'CRITICAL',
    filePath: '/s3.tf',
    fileLineRange: [1, 6],
    resource: 'aws_s3_bucket.public',
    guideline: null,
    ...over,
  };
}

function tfsecFinding(over: Partial<TfsecFinding> = {}): TfsecFinding {
  return {
    ruleId: 'AVD-AWS-0088',
    ruleDescription: 'Unencrypted S3 bucket.',
    severity: 'CRITICAL',
    status: 'failed',
    filePath: '/s3.tf',
    lineRange: [1, 6],
    resource: 'aws_s3_bucket.public',
    resolution: 'Configure bucket encryption',
    ...over,
  };
}

describe('categorizeCheckId — known IDs map to their category', () => {
  it('maps Checkov S3 encryption (CKV_AWS_19) to encryption-at-rest', () => {
    expect(categorizeCheckId('checkov', 'CKV_AWS_19')).toBe('encryption-at-rest');
  });

  it('maps Checkov IMDSv2 (CKV_AWS_79) to identity-and-access', () => {
    expect(categorizeCheckId('checkov', 'CKV_AWS_79')).toBe('identity-and-access');
  });

  it('maps Checkov open-SSH SG (CKV_AWS_24) to network-exposure', () => {
    expect(categorizeCheckId('checkov', 'CKV_AWS_24')).toBe('network-exposure');
  });

  it('maps tfsec S3 encryption (AVD-AWS-0088) to encryption-at-rest', () => {
    expect(categorizeCheckId('tfsec', 'AVD-AWS-0088')).toBe('encryption-at-rest');
  });

  it('maps tfsec IMDSv2 (AVD-AWS-0028) to identity-and-access', () => {
    expect(categorizeCheckId('tfsec', 'AVD-AWS-0028')).toBe('identity-and-access');
  });

  it('maps tfsec public-ingress-SGR (AVD-AWS-0107) to network-exposure', () => {
    expect(categorizeCheckId('tfsec', 'AVD-AWS-0107')).toBe('network-exposure');
  });
});

describe('categorizeCheckId — unknown IDs fall back to uncategorized', () => {
  it('returns uncategorized for an unknown Checkov ID', () => {
    expect(categorizeCheckId('checkov', 'CKV_AWS_99999')).toBe('uncategorized');
  });

  it('returns uncategorized for an unknown tfsec ID', () => {
    expect(categorizeCheckId('tfsec', 'AVD-AWS-9999')).toBe('uncategorized');
  });

  it('returns uncategorized for an empty rule ID', () => {
    expect(categorizeCheckId('checkov', '')).toBe('uncategorized');
  });
});

describe('normalizeSeverity — pass-through and fallback', () => {
  it('returns CRITICAL unchanged from checkov', () => {
    expect(normalizeSeverity('checkov', 'CRITICAL')).toBe('CRITICAL');
  });

  it('returns HIGH unchanged from tfsec', () => {
    expect(normalizeSeverity('tfsec', 'HIGH')).toBe('HIGH');
  });

  it('returns MEDIUM unchanged from checkov', () => {
    expect(normalizeSeverity('checkov', 'MEDIUM')).toBe('MEDIUM');
  });

  it('returns LOW unchanged from checkov', () => {
    expect(normalizeSeverity('checkov', 'LOW')).toBe('LOW');
  });

  it('null severity from checkov collapses to MEDIUM (visible but not loud)', () => {
    expect(normalizeSeverity('checkov', null)).toBe('MEDIUM');
  });

  it('undefined severity collapses to MEDIUM', () => {
    expect(normalizeSeverity('checkov', undefined)).toBe('MEDIUM');
  });
});

describe('aggregateFindings — empty inputs', () => {
  it('produces an empty report with zero counts when all three sources are empty', () => {
    const report = aggregateFindings(emptyCheckovReport(), emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toEqual([]);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.summary.bySeverity).toEqual({ LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
    expect(report.summary.byCategory).toEqual({
      'encryption-at-rest': 0,
      'encryption-in-transit': 0,
      'network-exposure': 0,
      'identity-and-access': 0,
      'logging-and-monitoring': 0,
      'secrets-management': 0,
      uncategorized: 0,
    });
  });
});

describe('aggregateFindings — single-source attribution', () => {
  it('a single Checkov finding with no tfsec match produces one AggregatedFinding with one source', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding()],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].sources).toEqual([
      { scanner: 'checkov', ruleId: 'CKV_AWS_19', originalSeverity: 'CRITICAL' },
    ]);
    expect(report.findings[0].category).toBe('encryption-at-rest');
    expect(report.findings[0].severity).toBe('CRITICAL');
  });

  it('a single tfsec finding with no Checkov match produces one AggregatedFinding with one source', () => {
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding()],
    };

    const report = aggregateFindings(emptyCheckovReport(), tfsec, emptyAwsContext());

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].sources).toEqual([
      { scanner: 'tfsec', ruleId: 'AVD-AWS-0088', originalSeverity: 'CRITICAL' },
    ]);
    expect(report.findings[0].category).toBe('encryption-at-rest');
  });
});

describe('aggregateFindings — deduplication on (category, resource)', () => {
  it('Checkov + tfsec S3-encryption on the same resource collapse into one AggregatedFinding with two sources', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding()], // CKV_AWS_19 on aws_s3_bucket.public
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding()], // AVD-AWS-0088 on aws_s3_bucket.public
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].category).toBe('encryption-at-rest');
    expect(report.findings[0].resource).toBe('aws_s3_bucket.public');
    expect(report.findings[0].sources).toHaveLength(2);
    expect(report.findings[0].sources.map((s) => s.scanner).sort()).toEqual(['checkov', 'tfsec']);
  });

  it('findings on the same category but different resources do NOT deduplicate', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ resource: 'aws_s3_bucket.one' }),
        checkovFinding({ resource: 'aws_s3_bucket.two' }),
      ],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toHaveLength(2);
    expect(report.findings.map((f) => f.resource).sort()).toEqual([
      'aws_s3_bucket.one',
      'aws_s3_bucket.two',
    ]);
  });
});

describe('aggregateFindings — severity reconciliation', () => {
  it('takes the max severity across deduplicated sources (MEDIUM + HIGH → HIGH)', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding({ severity: 'MEDIUM' })],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding({ severity: 'HIGH' })],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].severity).toBe('HIGH');
    // Originals are preserved on the sources entries.
    const sourceSeverities = report.findings[0].sources
      .map((s) => `${s.scanner}:${s.originalSeverity}`)
      .sort();
    expect(sourceSeverities).toEqual(['checkov:MEDIUM', 'tfsec:HIGH']);
  });

  it('takes CRITICAL when one source is CRITICAL and the other is LOW', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding({ severity: 'LOW' })],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding({ severity: 'CRITICAL' })],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    expect(report.findings[0].severity).toBe('CRITICAL');
  });

  it('on equal severity, description is taken from the Checkov source (tie-break)', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding({ severity: 'HIGH', checkName: 'CHECKOV-DESCRIPTION' })],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding({ severity: 'HIGH', ruleDescription: 'TFSEC-DESCRIPTION' })],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    expect(report.findings[0].description).toBe('CHECKOV-DESCRIPTION');
  });

  it('the higher-severity source supplies the description (overrides Checkov tie-break)', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding({ severity: 'LOW', checkName: 'CHECKOV-DESCRIPTION' })],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding({ severity: 'CRITICAL', ruleDescription: 'TFSEC-DESCRIPTION' })],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    expect(report.findings[0].description).toBe('TFSEC-DESCRIPTION');
  });
});

describe('aggregateFindings — uncategorized never deduplicates', () => {
  it('two uncategorized findings on the same resource produce two AggregatedFindings, not one', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ checkId: 'CKV_AWS_99991', resource: 'aws_thing.x', checkName: 'unknown-a' }),
        checkovFinding({ checkId: 'CKV_AWS_99992', resource: 'aws_thing.x', checkName: 'unknown-b' }),
      ],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toHaveLength(2);
    expect(report.findings.every((f) => f.category === 'uncategorized')).toBe(true);
    // Each carries exactly one source — they did not collapse despite shared resource.
    expect(report.findings.every((f) => f.sources.length === 1)).toBe(true);
  });

  it('an uncategorized Checkov finding does not deduplicate with an uncategorized tfsec finding on the same resource', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding({ checkId: 'CKV_AWS_99991', resource: 'aws_thing.x' })],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding({ ruleId: 'AVD-AWS-9999', resource: 'aws_thing.x' })],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    expect(report.findings).toHaveLength(2);
  });

  it('an uncategorized finding does not join a categorized group on the same resource', () => {
    // The mixed case: one known check ID and one unknown, both naming
    // aws_s3_bucket.x. The categorized row owns the (category, resource) key;
    // the uncategorized row must stay a separate finding rather than being
    // folded into it as a second source.
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ checkId: 'CKV_AWS_19', resource: 'aws_s3_bucket.x' }),
        checkovFinding({ checkId: 'CKV_AWS_99991', resource: 'aws_s3_bucket.x' }),
      ],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toHaveLength(2);
    expect(report.findings.every((f) => f.sources.length === 1)).toBe(true);
    const categories = report.findings.map((f) => f.category).sort();
    expect(categories).toEqual(['encryption-at-rest', 'uncategorized']);
  });
});

describe('aggregateFindings — reported severity is the max over sources', () => {
  // A property, asserted over every finding rather than a hand-picked one.
  //
  // aggregateFindings computes the reported severity with a max loop, while
  // pickRepresentative independently computes an argmax over the same group.
  // Those are two paths to the same number, and this is what pins them
  // together: if the representative's tie-break rule ever changes in a way that
  // stops tracking severity, or the max loop is "simplified" into
  // representative.severity, one of them moves and this fails.
  const RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;

  it('holds across a mixed multi-scanner report', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ checkId: 'CKV_AWS_19', resource: 'aws_s3_bucket.a', severity: 'LOW' }),
        checkovFinding({ checkId: 'CKV_AWS_24', resource: 'aws_sg.b', severity: 'MEDIUM' }),
        checkovFinding({ checkId: 'CKV_AWS_99991', resource: 'aws_thing.c', severity: 'HIGH' }),
      ],
    };
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [
        // Same (category, resource) as the LOW Checkov row above, at CRITICAL —
        // so the merged finding must report CRITICAL, not LOW.
        tfsecFinding({ ruleId: 'AVD-AWS-0088', resource: 'aws_s3_bucket.a', severity: 'CRITICAL' }),
        tfsecFinding({ ruleId: 'AVD-AWS-0107', resource: 'aws_sg.b', severity: 'LOW' }),
      ],
    };

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());

    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      const maxSourceRank = Math.max(...finding.sources.map((s) => RANK[s.originalSeverity]));
      expect(RANK[finding.severity]).toBe(maxSourceRank);
    }

    // Guard against the property holding only because nothing actually merged.
    const merged = report.findings.find((f) => f.sources.length > 1);
    expect(merged).toBeDefined();
    expect(merged!.severity).toBe('CRITICAL');
  });
});

describe('aggregateFindings — AWS context passthrough', () => {
  it('passes the AWS context report through unchanged into report.context', () => {
    const aws: AwsContextReport = {
      alb: { albCount: 2, albArns: ['arn:1', 'arn:2'] },
      imdsv2: {
        checked: [
          {
            serviceArn: 'arn:svc:1',
            serviceName: 'web',
            clusterArn: 'arn:cl:1',
            taskDefinitionArn: 'arn:td:1',
            platformVersion: 'LATEST',
            compliant: true,
          },
        ],
        compliantCount: 1,
        nonCompliantCount: 0,
      },
    };

    const report = aggregateFindings(emptyCheckovReport(), emptyTfsecReport(), aws);

    expect(report.context.alb).toEqual(aws.alb);
    expect(report.context.imdsv2).toEqual(aws.imdsv2);
  });
});

describe('aggregateFindings — summary counts match the findings array', () => {
  it('counts severity and category buckets exactly to the final findings list', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ checkId: 'CKV_AWS_19', severity: 'CRITICAL', resource: 'aws_s3_bucket.a' }),
        checkovFinding({ checkId: 'CKV_AWS_24', severity: 'MEDIUM', resource: 'aws_sg.b', checkName: 'sg' }),
        checkovFinding({ checkId: 'CKV_AWS_79', severity: 'HIGH', resource: 'aws_instance.c', checkName: 'imds' }),
      ],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.bySeverity).toEqual({ LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 1 });
    expect(report.summary.byCategory['encryption-at-rest']).toBe(1);
    expect(report.summary.byCategory['network-exposure']).toBe(1);
    expect(report.summary.byCategory['identity-and-access']).toBe(1);
  });
});

describe('aggregateFindings — deterministic ordering', () => {
  it('two runs over the same inputs produce deep-equal output', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        checkovFinding({ checkId: 'CKV_AWS_19', severity: 'CRITICAL', resource: 'aws_s3_bucket.b' }),
        checkovFinding({ checkId: 'CKV_AWS_24', severity: 'MEDIUM', resource: 'aws_sg.a', checkName: 'sg' }),
        checkovFinding({ checkId: 'CKV_AWS_79', severity: 'HIGH', resource: 'aws_instance.c', checkName: 'imds' }),
      ],
    };

    const a = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());
    const b = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());
    expect(a).toEqual(b);
  });

  it('orders by severity DESC, then category alpha, then resource alpha', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [
        // Two equal CRITICAL severities — should sort by category then resource.
        checkovFinding({ checkId: 'CKV_AWS_19', severity: 'CRITICAL', resource: 'aws_s3_bucket.z' }),
        checkovFinding({ checkId: 'CKV_AWS_19', severity: 'CRITICAL', resource: 'aws_s3_bucket.a' }),
        // One MEDIUM (network-exposure) and one HIGH (identity-and-access).
        checkovFinding({ checkId: 'CKV_AWS_24', severity: 'MEDIUM', resource: 'aws_sg.x', checkName: 'sg' }),
        checkovFinding({ checkId: 'CKV_AWS_79', severity: 'HIGH', resource: 'aws_instance.y', checkName: 'imds' }),
      ],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings.map((f) => [f.severity, f.category, f.resource])).toEqual([
      ['CRITICAL', 'encryption-at-rest', 'aws_s3_bucket.a'],
      ['CRITICAL', 'encryption-at-rest', 'aws_s3_bucket.z'],
      ['HIGH', 'identity-and-access', 'aws_instance.y'],
      ['MEDIUM', 'network-exposure', 'aws_sg.x'],
    ]);
  });
});

describe('aggregateFindings — single-scanner inputs produce sensible reports', () => {
  it('Checkov-only input yields correct counts and no crashes', () => {
    const checkov: CheckovReport = {
      ...emptyCheckovReport(),
      failed: [checkovFinding(), checkovFinding({ resource: 'aws_s3_bucket.other' })],
    };

    const report = aggregateFindings(checkov, emptyTfsecReport(), emptyAwsContext());

    expect(report.findings).toHaveLength(2);
    expect(report.summary.totalFindings).toBe(2);
    // Both sources should still be 'checkov' attribution.
    expect(report.findings.every((f) => f.sources.every((s) => s.scanner === 'checkov'))).toBe(true);
  });

  it('tfsec-only input yields correct counts and no crashes', () => {
    const tfsec: TfsecReport = {
      ...emptyTfsecReport(),
      failed: [tfsecFinding(), tfsecFinding({ resource: 'aws_s3_bucket.other' })],
    };

    const report = aggregateFindings(emptyCheckovReport(), tfsec, emptyAwsContext());

    expect(report.findings).toHaveLength(2);
    expect(report.summary.totalFindings).toBe(2);
    expect(report.findings.every((f) => f.sources.every((s) => s.scanner === 'tfsec'))).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Real-fixture end-to-end tests. We drive runCheckov and runTfsec through
// their fake-executor injection points so the reports we feed the aggregator
// are produced by the same code path as production. The fixtures' overlap
// (S3 encryption, IMDSv2, open SG) is exactly the dedup case in the wild.
// ─────────────────────────────────────────────────────────────────────────────

describe('Checkov+tfsec fixtures — S3 encryption, IMDSv2, open SG (real-world dedup)', () => {
  it('three overlapping themes deduplicate into three AggregatedFindings, each with two sources', async () => {
    const checkov = await runCheckov(CHECKOV_FIXTURE_DIR, makeCheckovExecutor(checkovFindingsStdout));
    const tfsec = await runTfsec(TFSEC_FIXTURE_DIR, makeTfsecExecutor(tfsecFindingsStdout));

    // Sanity check on the inputs themselves — the fixtures contain 3 failed
    // checkov findings and 3 failed tfsec findings (the 4th tfsec result is a
    // passed S3 versioning check, not surfaced into `failed`).
    expect(checkov.failed).toHaveLength(3);
    expect(tfsec.failed).toHaveLength(3);

    // BUT — the failed findings differ in one important way: the fixtures use
    // different file path conventions (Checkov uses `/s3.tf` while tfsec uses
    // `/repo/terraform/s3.tf`). filePath isn't part of the dedup key
    // (resource is), so they still collapse on (category, resource).
    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());

    expect(report.findings).toHaveLength(3);
    expect(report.findings.every((f) => f.sources.length === 2)).toBe(true);

    // Verify the three categories are covered.
    const categories = report.findings.map((f) => f.category).sort();
    expect(categories).toEqual(['encryption-at-rest', 'identity-and-access', 'network-exposure']);
  });

  it('CRITICAL severity wins on S3 encryption (both scanners say CRITICAL in fixture)', async () => {
    const checkov = await runCheckov(CHECKOV_FIXTURE_DIR, makeCheckovExecutor(checkovFindingsStdout));
    const tfsec = await runTfsec(TFSEC_FIXTURE_DIR, makeTfsecExecutor(tfsecFindingsStdout));

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    const s3 = report.findings.find((f) => f.category === 'encryption-at-rest');
    expect(s3?.severity).toBe('CRITICAL');
  });

  it('IMDSv2 finding reconciles HIGH (Checkov says HIGH, tfsec says HIGH; both sources retained)', async () => {
    const checkov = await runCheckov(CHECKOV_FIXTURE_DIR, makeCheckovExecutor(checkovFindingsStdout));
    const tfsec = await runTfsec(TFSEC_FIXTURE_DIR, makeTfsecExecutor(tfsecFindingsStdout));

    const report = aggregateFindings(checkov, tfsec, emptyAwsContext());
    const imds = report.findings.find((f) => f.category === 'identity-and-access');
    expect(imds?.severity).toBe('HIGH');
    expect(imds?.sources).toHaveLength(2);
  });
});
