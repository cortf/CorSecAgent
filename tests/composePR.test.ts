import { describe, it, expect, vi } from 'vitest';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { composePR, __testing } from '../src/reporter/composePR.js';
import {
  AnthropicLLMClient,
  type AnthropicSDKLike,
} from '../src/shared/llmClient.js';
import { FakeLLMClient } from './helpers/fakeLLMClient.js';

// -----------------------------------------------------------------------------
// Fixtures and helpers
// -----------------------------------------------------------------------------

const FIXTURE_DIR = fileURLToPath(new URL('../fixtures/reporter/', import.meta.url));

const FIX = {
  matchesWithFix: join(FIXTURE_DIR, 'matches-with-fix.json'),
  cortWithFix: join(FIXTURE_DIR, 'cort-report-with-fix.json'),
  sessionWithFix: join(FIXTURE_DIR, 'session-with-fix.json'),

  matchesTestsFailed: join(FIXTURE_DIR, 'matches-tests-failed.json'),
  cortTestsFailed: join(FIXTURE_DIR, 'cort-report-tests-failed.json'),
  sessionTestsFailed: join(FIXTURE_DIR, 'session-tests-failed.json'),

  matchesNoFix: join(FIXTURE_DIR, 'matches-no-fix.json'),
  cortNoFix: join(FIXTURE_DIR, 'cort-report-no-fix.json'),
  sessionNoFix: join(FIXTURE_DIR, 'session-no-fix.json'),

  matchesClean: join(FIXTURE_DIR, 'matches-clean.json'),
  cortClean: join(FIXTURE_DIR, 'cort-report-clean.json'),
  sessionClean: join(FIXTURE_DIR, 'session-clean.json'),
};

// A well-formed LLM response with all five required headers in order.
// Lives at module level so the assertion of its acceptability is itself a
// fixture that every test can rely on.
const WELL_FORMED_LLM_RESPONSE = [
  '## Risk Summary',
  'Patched HIGH-severity wrangler advisory GHSA-cfph-4qqh-w828.',
  '',
  '## Affected Dependencies',
  '- wrangler (GHSA-cfph-4qqh-w828, HIGH): env var exposure',
  '',
  '## Patches Applied',
  '- wrangler: 3.10.0 → 3.20.1 (patched-tests-passed)',
  '',
  '## Infrastructure Hardening',
  '- [HIGH] encryption-at-rest on aws_s3_bucket.app_logs: missing SSE (checkov, tfsec)',
  '',
  '## Test Results',
  'All tests passing after patch installation.',
].join('\n');

// One inspected Fargate service. decideMode now reads `checked` directly, so a
// test that wants "an account with N services" has to say which services —
// which is the point: the old literals asserted three compliant services with
// an empty `checked` array, and it was genuinely ambiguous which branch they
// were exercising.
function fargate(name: string, compliant = true) {
  return {
    serviceArn: `arn:aws:ecs:us-east-1:111111111111:service/prod/${name}`,
    serviceName: name,
    clusterArn: 'arn:aws:ecs:us-east-1:111111111111:cluster/prod',
    taskDefinitionArn: `arn:aws:ecs:us-east-1:111111111111:task-definition/${name}:1`,
    platformVersion: compliant ? 'LATEST' : '1.3.0',
    compliant,
  };
}

async function makeTmpOutput(): Promise<{
  outputPath: string;
  cleanup: () => Promise<void>;
}> {
  const dir = join(tmpdir(), `reporter-test-${randomUUID()}`);
  await mkdir(dir, { recursive: true });
  return {
    outputPath: join(dir, 'pr-description.md'),
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

// -----------------------------------------------------------------------------
// decideMode unit tests — exercise the mode picker without the file I/O.
// -----------------------------------------------------------------------------

describe('decideMode — template-only triggers', () => {
  it('picks template when patches all passed, Cort empty, no context concerns', () => {
    const cort = {
      findings: [],
      context: {
        alb: { albArns: ['arn:x'] },
        imdsv2: { checked: [fargate('web'), fargate('api')] },
      },
      summary: {
        totalFindings: 0,
        bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        byCategory: {
          'encryption-at-rest': 0,
          'encryption-in-transit': 0,
          'network-exposure': 0,
          'identity-and-access': 0,
          'logging-and-monitoring': 0,
          'secrets-management': 0,
          uncategorized: 0,
        },
      },
    } as const;
    const session = {
      branchName: 'b/1',
      results: [
        {
          packageName: 'lodash',
          previousVersion: '4.17.20',
          targetVersion: '4.17.21',
          installedVersion: '4.17.21',
          status: 'patched-tests-passed',
          relatedMatches: ['GHSA-x'],
          errorMessage: null,
        },
      ],
      testRun: { status: 'passed', output: 'ok' },
      summary: { total: 1, byStatus: {
          'patched-tests-passed': 1,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        } },
    } as const;
    expect(__testing.decideMode(cort, session)).toBe('template');
  });

  it('picks template on empty patches when account has no services or ALBs', () => {
    const cort = {
      findings: [],
      context: {
        alb: { albArns: [] },
        imdsv2: { checked: [] },
      },
      summary: {
        totalFindings: 0,
        bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        byCategory: {
          'encryption-at-rest': 0,
          'encryption-in-transit': 0,
          'network-exposure': 0,
          'identity-and-access': 0,
          'logging-and-monitoring': 0,
          'secrets-management': 0,
          uncategorized: 0,
        },
      },
    } as const;
    const session = {
      branchName: 'b/1',
      results: [],
      testRun: null,
      summary: {
        total: 0,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      },
    } as const;
    expect(__testing.decideMode(cort, session)).toBe('template');
  });
});

describe('decideMode — LLM-call triggers', () => {
  function cleanCort() {
    return {
      findings: [],
      context: {
        alb: { albArns: ['arn:x'] },
        imdsv2: { checked: [fargate('web')] },
      },
      summary: {
        totalFindings: 0,
        bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        byCategory: {
          'encryption-at-rest': 0,
          'encryption-in-transit': 0,
          'network-exposure': 0,
          'identity-and-access': 0,
          'logging-and-monitoring': 0,
          'secrets-management': 0,
          uncategorized: 0,
        },
      },
    } as const;
  }

  function passingSession() {
    return {
      branchName: 'b/1',
      results: [
        {
          packageName: 'lodash',
          previousVersion: '4.17.20',
          targetVersion: '4.17.21',
          installedVersion: '4.17.21',
          status: 'patched-tests-passed',
          relatedMatches: ['GHSA-x'],
          errorMessage: null,
        },
      ],
      testRun: { status: 'passed', output: 'ok' },
      summary: { total: 1, byStatus: {
          'patched-tests-passed': 1,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        } },
    } as const;
  }

  it('picks LLM when any patch failed tests', () => {
    const session = passingSession();
    const failedSession = {
      ...session,
      results: [{ ...session.results[0]!, status: 'patched-tests-failed' }],
    } as const;
    expect(__testing.decideMode(cleanCort(), failedSession)).toBe('llm');
  });

  it('picks LLM on no-fix-available patches', () => {
    const session = passingSession();
    const noFixSession = {
      ...session,
      results: [{ ...session.results[0]!, status: 'patch-failed-no-fix-available' }],
    } as const;
    expect(__testing.decideMode(cleanCort(), noFixSession)).toBe('llm');
  });

  it('picks LLM on install-error patches', () => {
    const session = passingSession();
    const installErrSession = {
      ...session,
      results: [{ ...session.results[0]!, status: 'patch-failed-install-error' }],
    } as const;
    expect(__testing.decideMode(cleanCort(), installErrSession)).toBe('llm');
  });

  it('picks LLM when Cort has any findings', () => {
    const cort = cleanCort();
    const withFindings = {
      ...cort,
      findings: [
        {
          category: 'encryption-at-rest',
          severity: 'HIGH',
          resource: 'aws_s3_bucket.x',
          filePath: '/s3.tf',
          lineRange: [1, 2],
          description: 'No SSE.',
          sources: [{ scanner: 'checkov', ruleId: 'CKV_AWS_19', originalSeverity: 'HIGH' }],
        },
      ],
    } as const;
    expect(__testing.decideMode(withFindings, passingSession())).toBe('llm');
  });

  it('picks LLM when imdsv2 non-compliant', () => {
    const cort = cleanCort();
    const nonCompliant = {
      ...cort,
      context: {
        ...cort.context,
        imdsv2: { checked: [fargate('web'), fargate('api', false), fargate('worker', false)] },
      },
    } as const;
    expect(__testing.decideMode(nonCompliant, passingSession())).toBe('llm');
  });

  it('picks LLM when Fargate services exist but no ALBs are deployed', () => {
    const cort = cleanCort();
    const noAlbs = {
      ...cort,
      context: {
        alb: { albArns: [] as string[] },
        imdsv2: { checked: [fargate('web'), fargate('api'), fargate('worker')] },
      },
    } as const;
    expect(__testing.decideMode(noAlbs, passingSession())).toBe('llm');
  });
});

// -----------------------------------------------------------------------------
// validateSections — independent of the rest of the module so a regression
// in the validator is caught directly, not via a composePR end-to-end test.
// -----------------------------------------------------------------------------

describe('validateSections', () => {
  it('accepts a well-formed response with all five headers in order', () => {
    expect(() => __testing.validateSections(WELL_FORMED_LLM_RESPONSE)).not.toThrow();
  });

  it('rejects output missing a section', () => {
    const broken = WELL_FORMED_LLM_RESPONSE.replace('## Test Results', '');
    expect(() => __testing.validateSections(broken)).toThrow(/Test Results/);
  });

  it('rejects output with sections out of order', () => {
    // Move "## Test Results" before "## Risk Summary" — the validator scans
    // forward from a moving cursor, so this should fail on Risk Summary
    // missing AFTER the displaced Test Results, or on Test Results missing
    // after the cursor advances past where it expected. Either way, throws.
    const swapped = [
      '## Test Results',
      'All tests passing.',
      '## Risk Summary',
      'Patched.',
      '## Affected Dependencies',
      'None.',
      '## Patches Applied',
      'None.',
      '## Infrastructure Hardening',
      'None.',
    ].join('\n');
    expect(() => __testing.validateSections(swapped)).toThrow();
  });
});

// -----------------------------------------------------------------------------
// composePR — template-only path
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// renderTemplate — exported for tests but, until now, never actually called by
// one. Both template-mode tests went through composePR with a one-result
// fixture, so neither the empty-session document nor the pluralisation
// branches had any coverage.
// -----------------------------------------------------------------------------

describe('renderTemplate — empty session', () => {
  function emptySession() {
    return {
      branchName: 'corsec/hotfix/1',
      results: [],
      testRun: null,
      summary: {
        total: 0,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      },
    } as const;
  }

  // Byte-for-byte, because a dropped blank line between a header and its
  // bullets breaks markdown list rendering in a real PR body, and the document
  // deliberately has no trailing newline.
  const EXPECTED =
    '## Risk Summary\nNone.\n\n' +
    '## Affected Dependencies\nNone.\n\n' +
    '## Patches Applied\nNone.\n\n' +
    '## Infrastructure Hardening\nNone.\n\n' +
    '## Test Results\nNo tests run (no patches applied).';

  it('renders the exact five-section empty document', () => {
    expect(__testing.renderTemplate(emptySession())).toBe(EXPECTED);
  });

  it('produces a document the section validator accepts', () => {
    expect(() =>
      __testing.validateSections(__testing.renderTemplate(emptySession())),
    ).not.toThrow();
  });
});

describe('renderTemplate — pluralisation', () => {
  function result(packageName: string, ghsas: string[]) {
    return {
      packageName,
      previousVersion: '1.0.0',
      targetVersion: '2.0.0',
      installedVersion: '2.0.1',
      status: 'patched-tests-passed',
      relatedMatches: ghsas,
      errorMessage: null,
    } as const;
  }

  function sessionWith(results: ReturnType<typeof result>[]) {
    return {
      branchName: 'corsec/hotfix/1',
      results,
      testRun: { status: 'passed', output: 'ok' },
      summary: {
        total: results.length,
        byStatus: {
          'patched-tests-passed': results.length,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      },
    } as const;
  }

  it('uses the singular for one patch across one package', () => {
    const md = __testing.renderTemplate(sessionWith([result('a', ['GHSA-1'])]));
    expect(md).toContain('Applied 1 security patch across 1 package.');
  });

  it('uses the plural for several patches across several packages', () => {
    const md = __testing.renderTemplate(
      sessionWith([result('a', ['GHSA-1', 'GHSA-2']), result('b', ['GHSA-3'])]),
    );
    expect(md).toContain('Applied 3 security patches across 2 packages.');
  });

  it('lists every package under both Affected Dependencies and Patches Applied', () => {
    const md = __testing.renderTemplate(
      sessionWith([result('a', ['GHSA-1']), result('b', ['GHSA-2'])]),
    );
    expect(md).toContain('- a: GHSA-1');
    expect(md).toContain('- b: GHSA-2');
    expect(md).toContain('- a: 1.0.0 → 2.0.1 (patched-tests-passed)');
    expect(md).toContain('- b: 1.0.0 → 2.0.1 (patched-tests-passed)');
  });

  it('falls back to the previous version when installedVersion is null', () => {
    const rows = [{ ...result('a', ['GHSA-1']), installedVersion: null }] as const;
    const md = __testing.renderTemplate(sessionWith([...rows]));
    expect(md).toContain('- a: 1.0.0 → 1.0.0 (patched-tests-passed)');
  });
});

describe('composePR — template-only mode', () => {
  it('uses template mode for the clean fixture and never calls the LLM', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient('SHOULD NOT BE USED');
    try {
      const md = await composePR(
        {
          matchesPath: FIX.matchesClean,
          cortReportPath: FIX.cortClean,
          patchSessionPath: FIX.sessionClean,
          outputPath: outputPath,
        },
        fake,
      );
      expect(fake.calls).toHaveLength(0);
      // Five section headers must all appear, in order.
      for (const header of __testing.REQUIRED_SECTIONS) {
        expect(md).toContain(header);
      }
      // The deterministic template names the package and the upgrade.
      expect(md).toContain('lodash');
      expect(md).toContain('4.17.20');
      expect(md).toContain('4.17.21');
      // Written to outputPath verbatim.
      const onDisk = await readFile(outputPath, 'utf-8');
      expect(onDisk).toBe(md);
    } finally {
      await cleanup();
    }
  });

  it('emits headers in the exact required order in template output', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient('SHOULD NOT BE USED');
    try {
      const md = await composePR(
        {
          matchesPath: FIX.matchesClean,
          cortReportPath: FIX.cortClean,
          patchSessionPath: FIX.sessionClean,
          outputPath: outputPath,
        },
        fake,
      );
      const indices = __testing.REQUIRED_SECTIONS.map((h) => md.indexOf(h));
      const sorted = [...indices].sort((a, b) => a - b);
      expect(indices).toEqual(sorted);
      expect(indices.every((i) => i >= 0)).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// composePR — LLM path
// -----------------------------------------------------------------------------

describe('composePR — LLM mode (tests-failed scenario)', () => {
  it('calls the LLM with the template system prompt and a trimmed user payload', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient(WELL_FORMED_LLM_RESPONSE);
    try {
      const md = await composePR(
        {
          matchesPath: FIX.matchesTestsFailed,
          cortReportPath: FIX.cortTestsFailed,
          patchSessionPath: FIX.sessionTestsFailed,
          outputPath: outputPath,
        },
        fake,
      );
      expect(fake.calls).toHaveLength(1);
      const call = fake.calls[0]!;

      // The system prompt is the on-disk template file. Spot-check on a
      // distinctive section the template contains.
      expect(call.systemPrompt).toContain('senior security engineer');
      expect(call.systemPrompt).toContain('## Risk Summary');

      // The user message must be JSON with exactly the three trimmed keys.
      const parsed = JSON.parse(call.userMessage) as Record<string, unknown>;
      expect(Object.keys(parsed).sort()).toEqual([
        'infrastructure',
        'patches',
        'vulnerabilities',
      ]);

      // The trimmed patch payload carries no noisy fields.
      const patches = parsed['patches'] as Array<Record<string, unknown>>;
      expect(patches[0]!['errorMessage']).toBeUndefined();
      expect(patches[0]!['packageName']).toBe('wrangler');

      // Captured test output never reaches the model — it lives on the session
      // as testRun and is deliberately not a payload key.
      expect(parsed['testRun']).toBeUndefined();
      expect(call.userMessage).not.toContain('Test Files');

      // The model-facing contract is still counts, even though the report no
      // longer stores them: prompts/pr-description.md names albCount,
      // compliantCount and nonCompliantCount, so they are derived at this
      // boundary. cort-report-tests-failed.json has 1 ALB arn and 2 compliant
      // services in `checked`.
      const infra = parsed['infrastructure'] as {
        context: {
          alb: { albCount: number };
          imdsv2: { compliantCount: number; nonCompliantCount: number };
        };
      };
      expect(infra.context.alb.albCount).toBe(1);
      expect(infra.context.imdsv2.compliantCount).toBe(2);
      expect(infra.context.imdsv2.nonCompliantCount).toBe(0);

      // Output is the FakeLLMClient's canned response, verbatim.
      expect(md).toBe(WELL_FORMED_LLM_RESPONSE);
      const onDisk = await readFile(outputPath, 'utf-8');
      expect(onDisk).toBe(WELL_FORMED_LLM_RESPONSE);
    } finally {
      await cleanup();
    }
  });

  it('triggers LLM mode on a no-fix-available patch even with empty Cort', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient(WELL_FORMED_LLM_RESPONSE);
    try {
      await composePR(
        {
          matchesPath: FIX.matchesNoFix,
          cortReportPath: FIX.cortNoFix,
          patchSessionPath: FIX.sessionNoFix,
          outputPath: outputPath,
        },
        fake,
      );
      expect(fake.calls).toHaveLength(1);
    } finally {
      await cleanup();
    }
  });

  it('triggers LLM mode when Cort has findings even if every patch passed', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient(WELL_FORMED_LLM_RESPONSE);
    try {
      await composePR(
        {
          matchesPath: FIX.matchesWithFix,
          cortReportPath: FIX.cortWithFix,
          patchSessionPath: FIX.sessionWithFix,
          outputPath: outputPath,
        },
        fake,
      );
      expect(fake.calls).toHaveLength(1);
    } finally {
      await cleanup();
    }
  });

  it('rejects a malformed LLM response (missing sections)', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient(
      '## Risk Summary\nSome text but no other sections.',
    );
    try {
      await expect(
        composePR(
          {
            matchesPath: FIX.matchesTestsFailed,
            cortReportPath: FIX.cortTestsFailed,
            patchSessionPath: FIX.sessionTestsFailed,
            outputPath: outputPath,
          },
          fake,
        ),
      ).rejects.toThrow(/Affected Dependencies/);
    } finally {
      await cleanup();
    }
  });

  it('uses the configured Sonnet model and maxTokens=800', async () => {
    const { outputPath, cleanup } = await makeTmpOutput();
    const fake = new FakeLLMClient(WELL_FORMED_LLM_RESPONSE);
    try {
      await composePR(
        {
          matchesPath: FIX.matchesTestsFailed,
          cortReportPath: FIX.cortTestsFailed,
          patchSessionPath: FIX.sessionTestsFailed,
          outputPath: outputPath,
        },
        fake,
      );
      const call = fake.calls[0]!;
      expect(call.model).toBe(__testing.REPORTER_MODEL);
      expect(call.maxTokens).toBe(800);
    } finally {
      await cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// Payload size assertion — proves the size guard is real, not aspirational.
// -----------------------------------------------------------------------------

describe('composePR — payload size budget', () => {
  it('throws when the serialized user-message exceeds 6000 chars', async () => {
    // Generate a synthetic over-budget matches payload by repeating a long
    // summary string. The fixture itself is too small to ever blow the cap,
    // so we write a one-off oversize fixture into a tmp dir.
    const dir = join(tmpdir(), `reporter-oversize-${randomUUID()}`);
    await mkdir(dir, { recursive: true });
    const matchesPath = join(dir, 'matches.json');
    const cortPath = join(dir, 'cort.json');
    const sessionPath = join(dir, 'session.json');
    const outputPath = join(dir, 'pr.md');

    const bigSummary = 'x'.repeat(500);
    const oversizeMatches = Array.from({ length: 30 }, (_, i) => ({
      ghsaId: `GHSA-${i.toString().padStart(4, '0')}-aaaa-bbbb`,
      packageName: `pkg-${i}`,
      installedVersion: '1.0.0',
      vulnerableRange: '>= 0.0.0',
      patchedVersion: '2.0.0',
      severity: 'HIGH',
      cvssScore: 7.5,
      summary: bigSummary,
    }));

    await writeFile(matchesPath, JSON.stringify(oversizeMatches), 'utf-8');
    // Cort is empty — but a no-fix patch forces LLM mode so the size guard
    // runs. We use tests-failed status to force LLM mode.
    await writeFile(cortPath, await readFile(FIX.cortTestsFailed, 'utf-8'), 'utf-8');
    await writeFile(
      sessionPath,
      JSON.stringify({
        branchName: 'b/oversize',
        results: [
          {
            packageName: 'pkg-0',
            previousVersion: '1.0.0',
            targetVersion: '2.0.0',
            installedVersion: '2.0.0',
            status: 'patched-tests-failed',
            relatedMatches: ['GHSA-0000-aaaa-bbbb'],
            errorMessage: null,
          },
        ],
        testRun: { status: 'failed', output: 'boom' },
        summary: {
          total: 1,
          byStatus: {
            'patched-tests-passed': 0,
            'patched-tests-failed': 1,
            'patch-failed-install-error': 0,
            'patch-failed-no-fix-available': 0,
            'skipped-already-resolved': 0,
          },
        },
      }),
      'utf-8',
    );

    const fake = new FakeLLMClient(WELL_FORMED_LLM_RESPONSE);
    try {
      await expect(
        composePR(
          {
            matchesPath: matchesPath,
            cortReportPath: cortPath,
            patchSessionPath: sessionPath,
            outputPath: outputPath,
          },
          fake,
        ),
      ).rejects.toThrow(/over the 6000-char budget/);
      // LLM must not be called when the payload is rejected.
      expect(fake.calls).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// -----------------------------------------------------------------------------
// AnthropicLLMClient wrapper — exercise the cost-log line via an SDK stub.
// -----------------------------------------------------------------------------

describe('AnthropicLLMClient', () => {
  it('emits [llm-cost] log line with token counts and model from a successful call', async () => {
    const stubSdk: AnthropicSDKLike = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ type: 'text', text: 'hello' }],
          usage: { input_tokens: 123, output_tokens: 45 },
        }),
      },
    };
    const client = new AnthropicLLMClient(stubSdk);

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const result = await client.complete({
        model: 'claude-sonnet-4-6',
        systemPrompt: 'system',
        userMessage: 'user',
        maxTokens: 100,
      });
      expect(result).toEqual({ text: 'hello', inputTokens: 123, outputTokens: 45 });
      const calls = logSpy.mock.calls.map((c) => c.join(' '));
      expect(calls.some((line) => /\[llm-cost\] input=123 output=45 model=claude-sonnet-4-6/.test(line))).toBe(true);
    } finally {
      logSpy.mockRestore();
    }
  });

  it('throws a clear error when ANTHROPIC_API_KEY is missing and no SDK is injected', () => {
    const prior = process.env['ANTHROPIC_API_KEY'];
    delete process.env['ANTHROPIC_API_KEY'];
    try {
      expect(() => new AnthropicLLMClient()).toThrow(/ANTHROPIC_API_KEY/);
    } finally {
      if (prior !== undefined) process.env['ANTHROPIC_API_KEY'] = prior;
    }
  });

  it('concatenates multiple text blocks in the response', async () => {
    const stubSdk: AnthropicSDKLike = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [
            { type: 'text', text: 'part1 ' },
            { type: 'text', text: 'part2' },
          ],
          usage: { input_tokens: 1, output_tokens: 2 },
        }),
      },
    };
    const client = new AnthropicLLMClient(stubSdk);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const result = await client.complete({
        model: 'claude-sonnet-4-6',
        systemPrompt: 's',
        userMessage: 'u',
        maxTokens: 10,
      });
      expect(result.text).toBe('part1 part2');
    } finally {
      logSpy.mockRestore();
    }
  });
});
