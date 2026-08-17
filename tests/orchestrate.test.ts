import { describe, it, expect, vi } from 'vitest';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { orchestrate, type OrchestrateOptions, type OrchestrationSummary } from '../src/orchestrate.js';
import type { Ecosystem, MatchedThreat } from '../src/hunter/types.js';
import type {
  AwsContextReport,
  CheckovReport,
  TfsecReport,
} from '../src/cort/types.js';
import { aggregateFindings } from '../src/cort/aggregateFindings.js';
import type { PatchSession } from '../src/patcher/types.js';
import type { LLMClient } from '../src/shared/llmClient.js';

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

async function makeTmpDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = join(tmpdir(), `orchestrate-test-${randomUUID()}`);
  await mkdir(dir, { recursive: true });
  return {
    dir,
    cleanup: async () => {
      await rm(dir, { recursive: true, force: true });
    },
  };
}

function baseOpts(outputDir: string, overrides: Partial<OrchestrateOptions> = {}): OrchestrateOptions {
  return {
    workingDir: '/tmp/working-dir-not-used',
    outputDir,
    testCommand: 'npm test',
    ecosystem: 'NPM' as Ecosystem,
    dryRun: true,
    ...overrides,
  };
}

function emptyCheckovReport(): CheckovReport {
  return { passed: [], failed: [], skipped: [] };
}

function emptyTfsecReport(): TfsecReport {
  return { passed: [], failed: [] };
}

function emptyAwsContextReport(): AwsContextReport {
  return {
    alb: { albArns: [] },
    imdsv2: { checked: [] },
  };
}

function happyPatchSession(): PatchSession {
  return {
    branchName: 'corsec/hotfix/1700000000',
    results: [
      {
        packageName: 'lodash',
        previousVersion: '4.17.20',
        targetVersion: '4.17.21',
        installedVersion: '4.17.21',
        status: 'patched-tests-passed',
        relatedMatches: ['GHSA-test-0001'],
        errorMessage: null,
      },
    ],
    testRun: { status: 'passed', output: 'ok' },
    summary: {
      total: 1,
      byStatus: {
        'patched-tests-passed': 1,
        'patched-tests-failed': 0,
        'patch-failed-install-error': 0,
        'patch-failed-no-fix-available': 0,
        'skipped-already-resolved': 0,
      },
    },
  };
}

// Build a `runHunter`-shaped fake: writes the supplied matches array (if any)
// to `outputPath`, then returns { matchCount } so the orchestrator sees the
// same on-disk artefact the real Hunter would produce.
function makeFakeHunter(matches: MatchedThreat[]) {
  return vi.fn(async (opts: { outputPath: string }) => {
    await writeFile(opts.outputPath, JSON.stringify(matches), 'utf-8');
    return { matchCount: matches.length };
  });
}

// Build a `composePR`-shaped fake: writes a fixed markdown to outputPath.
function makeFakeComposePR(markdown = '## ok') {
  return vi.fn(async (opts: { outputPath: string }) => {
    await writeFile(opts.outputPath, markdown, 'utf-8');
    return markdown;
  });
}

// Build an `applyPatches` fake that writes the supplied session to disk.
function makeFakeApplyPatches(session: PatchSession) {
  return vi.fn(async (opts: { outputPath: string }) => {
    await writeFile(opts.outputPath, JSON.stringify(session), 'utf-8');
    return session;
  });
}

import { writeFile } from 'node:fs/promises';

function makeFakeLLMClient(): LLMClient & { calls: number } {
  const client = {
    calls: 0,
    async complete() {
      client.calls++;
      return { text: 'unused', inputTokens: 100, outputTokens: 50 };
    },
  };
  return client as LLMClient & { calls: number };
}

// One sample MatchedThreat — content is irrelevant to the orchestrator, only
// the array-length matters because Hunter's contract is "matches.length tells
// you whether to continue".
const SAMPLE_MATCH: MatchedThreat = {
  ghsaId: 'GHSA-test-0001',
  packageName: 'lodash',
  installedVersion: '4.17.20',
  vulnerableRange: '< 4.17.21',
  patchedVersion: '4.17.21',
  severity: 'HIGH',
  cvssScore: 7.5,
  summary: 'Prototype pollution',
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

describe('orchestrate — Hunter empty result', () => {
  it('exits with code 0 and does not invoke Cort / Patcher / Reporter', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeHunter = makeFakeHunter([]);
      const fakeCheckov = vi.fn();
      const fakeTfsec = vi.fn();
      const fakeAws = vi.fn();
      const fakePatcher = vi.fn();
      const fakeComposePR = vi.fn();

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: fakeHunter,
        runCheckov: fakeCheckov,
        runTfsec: fakeTfsec,
        runAwsContextChecks: fakeAws,
        applyPatches: fakePatcher,
        composePR: fakeComposePR,
      });

      expect(summary.finalExitCode).toBe(0);
      expect(summary.matchCount).toBe(0);
      expect(fakeHunter).toHaveBeenCalledOnce();
      expect(fakeCheckov).not.toHaveBeenCalled();
      expect(fakeTfsec).not.toHaveBeenCalled();
      expect(fakeAws).not.toHaveBeenCalled();
      expect(fakePatcher).not.toHaveBeenCalled();
      expect(fakeComposePR).not.toHaveBeenCalled();

      const stages = summary.stages.map((s) => s.name);
      expect(stages).toEqual(['hunter']);

      // Summary file is written even on early-success exit.
      const onDisk = JSON.parse(
        await readFile(join(dir, 'orchestration-summary.json'), 'utf-8'),
      ) as OrchestrationSummary;
      expect(onDisk.finalExitCode).toBe(0);
      expect(onDisk.matchCount).toBe(0);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — Hunter throws', () => {
  it('exits with code 1, writes summary, and does not run later stages', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeHunter = vi.fn().mockRejectedValue(new Error('Hunter boom'));
      const fakeCheckov = vi.fn();
      const fakePatcher = vi.fn();
      const fakeComposePR = vi.fn();

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: fakeHunter,
        runCheckov: fakeCheckov,
        applyPatches: fakePatcher,
        composePR: fakeComposePR,
      });

      expect(summary.finalExitCode).toBe(1);
      expect(fakeCheckov).not.toHaveBeenCalled();
      expect(fakePatcher).not.toHaveBeenCalled();
      expect(fakeComposePR).not.toHaveBeenCalled();

      const hunterStage = summary.stages.find((s) => s.name === 'hunter');
      expect(hunterStage?.status).toBe('failed');
      expect(hunterStage?.errorMessage).toMatch(/Hunter boom/);

      // Summary file written even on failure.
      const onDisk = JSON.parse(
        await readFile(join(dir, 'orchestration-summary.json'), 'utf-8'),
      ) as OrchestrationSummary;
      expect(onDisk.finalExitCode).toBe(1);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — single Cort scanner fails', () => {
  it('runs the other scanners, aggregator gets empty inputs from the failed scanner, pipeline continues', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeCheckov = vi.fn().mockRejectedValue(new Error('checkov crashed'));
      const fakeTfsec = vi.fn().mockResolvedValue(emptyTfsecReport());
      const fakeAws = vi.fn().mockResolvedValue(emptyAwsContextReport());
      const fakePatcher = makeFakeApplyPatches(happyPatchSession());
      const fakeComposePR = makeFakeComposePR();

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: fakeCheckov,
        runTfsec: fakeTfsec,
        runAwsContextChecks: fakeAws,
        applyPatches: fakePatcher,
        composePR: fakeComposePR,
        llmClient: makeFakeLLMClient(),
      });

      expect(summary.finalExitCode).toBe(0);
      expect(fakeCheckov).toHaveBeenCalled();
      expect(fakeTfsec).toHaveBeenCalled();
      expect(fakeAws).toHaveBeenCalled();
      expect(fakePatcher).toHaveBeenCalledOnce();
      expect(fakeComposePR).toHaveBeenCalledOnce();

      const cortStage = summary.stages.find((s) => s.name === 'cort');
      expect(cortStage?.subStages).toEqual({
        checkov: 'failed',
        tfsec: 'success',
        awsContext: 'success',
      });
      // At least one scanner succeeded → overall cort stage is 'success'
      expect(cortStage?.status).toBe('success');
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — every Cort scanner fails', () => {
  // The all-three-fail rollup had no coverage at all, which made it the one
  // branch a refactor of this block could silently invert.
  it('marks the cort stage failed while still running Patcher and Reporter', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeComposePR = makeFakeComposePR();
      const fakePatcher = makeFakeApplyPatches(happyPatchSession());

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: vi.fn().mockRejectedValue(new Error('checkov crashed')),
        runTfsec: vi.fn().mockRejectedValue(new Error('tfsec crashed')),
        runAwsContextChecks: vi.fn().mockRejectedValue(new Error('aws crashed')),
        applyPatches: fakePatcher,
        composePR: fakeComposePR,
        llmClient: makeFakeLLMClient(),
      });

      const cortStage = summary.stages.find((s) => s.name === 'cort');
      expect(cortStage?.status).toBe('failed');
      expect(cortStage?.subStages).toEqual({
        checkov: 'failed',
        tfsec: 'failed',
        awsContext: 'failed',
      });

      // Degradation, not abort: a totally failed Cort stage must not stop the
      // pipeline, and the run still exits 0.
      expect(fakePatcher).toHaveBeenCalledOnce();
      expect(fakeComposePR).toHaveBeenCalledOnce();
      expect(summary.finalExitCode).toBe(0);
    } finally {
      await cleanup();
    }
  });

  it('logs the AWS sub-stage failure under the label "aws-context", not the sub-stage key', async () => {
    const { dir, cleanup } = await makeTmpDir();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: vi.fn().mockRejectedValue(new Error('checkov crashed')),
        runTfsec: vi.fn().mockRejectedValue(new Error('tfsec crashed')),
        runAwsContextChecks: vi.fn().mockRejectedValue(new Error('aws crashed')),
        applyPatches: makeFakeApplyPatches(happyPatchSession()),
        composePR: makeFakeComposePR(),
        llmClient: makeFakeLLMClient(),
      });

      const logged = errorSpy.mock.calls.map((c) => String(c[0]));
      expect(logged).toContainEqual(expect.stringContaining('aws-context failed'));
      expect(logged).toContainEqual(expect.stringContaining('checkov failed'));
      expect(logged).toContainEqual(expect.stringContaining('tfsec failed'));
    } finally {
      errorSpy.mockRestore();
      await cleanup();
    }
  });
});

describe('orchestrate — empty Cort report', () => {
  // cort-report.json must stay byte-identical: composePR's decideMode reads
  // albCount / nonCompliantCount / compliantCount off it, so any drift in this
  // artefact silently flips the pipeline into a billable LLM call.
  it('writes exactly what aggregating the three empty scanner reports produces', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      await orchestrate(baseOpts(dir), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        applyPatches: makeFakeApplyPatches(happyPatchSession()),
        composePR: makeFakeComposePR(),
        llmClient: makeFakeLLMClient(),
      });

      const onDisk = await readFile(join(dir, 'cort-report.json'), 'utf-8');
      const expected = JSON.stringify(
        aggregateFindings(emptyCheckovReport(), emptyTfsecReport(), emptyAwsContextReport()),
        null,
        2,
      );
      expect(onDisk).toBe(expected);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — Patcher throws', () => {
  it('writes a synthetic empty PatchSession and still runs the Reporter', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakePatcher = vi.fn().mockRejectedValue(new Error('patcher exploded'));
      const fakeComposePR = makeFakeComposePR();

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: vi.fn().mockResolvedValue(emptyCheckovReport()),
        runTfsec: vi.fn().mockResolvedValue(emptyTfsecReport()),
        runAwsContextChecks: vi.fn().mockResolvedValue(emptyAwsContextReport()),
        applyPatches: fakePatcher,
        composePR: fakeComposePR,
        llmClient: makeFakeLLMClient(),
      });

      expect(summary.finalExitCode).toBe(0);
      expect(fakeComposePR).toHaveBeenCalledOnce();

      const patcherStage = summary.stages.find((s) => s.name === 'patcher');
      expect(patcherStage?.status).toBe('failed');
      expect(patcherStage?.errorMessage).toMatch(/patcher exploded/);

      // The synthetic session must be persisted so the reporter can read it.
      const session = JSON.parse(
        await readFile(join(dir, 'patch-session.json'), 'utf-8'),
      ) as PatchSession;
      expect(session.results).toEqual([]);
      expect(session.summary.total).toBe(0);
      expect(session.testRun).toBeNull();
      expect(session.branchName).toMatch(/^corsec\/hotfix\//);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — Reporter throws', () => {
  it('exits with code 1 but artifacts written through that point still exist', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeComposePR = vi.fn().mockRejectedValue(new Error('reporter broke'));

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: vi.fn().mockResolvedValue(emptyCheckovReport()),
        runTfsec: vi.fn().mockResolvedValue(emptyTfsecReport()),
        runAwsContextChecks: vi.fn().mockResolvedValue(emptyAwsContextReport()),
        applyPatches: makeFakeApplyPatches(happyPatchSession()),
        composePR: fakeComposePR,
        llmClient: makeFakeLLMClient(),
      });

      expect(summary.finalExitCode).toBe(1);
      // All upstream artefacts written:
      await expect(readFile(join(dir, 'hunter-matches.json'), 'utf-8')).resolves.toBeDefined();
      await expect(readFile(join(dir, 'cort-report.json'), 'utf-8')).resolves.toBeDefined();
      await expect(readFile(join(dir, 'patch-session.json'), 'utf-8')).resolves.toBeDefined();

      const reporterStage = summary.stages.find((s) => s.name === 'reporter');
      expect(reporterStage?.status).toBe('failed');
      expect(reporterStage?.errorMessage).toMatch(/reporter broke/);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — no --terraform-dir provided', () => {
  it('skips every Cort sub-stage, reporter still runs with an empty Cort report', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeCheckov = vi.fn();
      const fakeTfsec = vi.fn();
      const fakeAws = vi.fn();
      const fakeComposePR = makeFakeComposePR();

      const summary = await orchestrate(baseOpts(dir), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: fakeCheckov,
        runTfsec: fakeTfsec,
        runAwsContextChecks: fakeAws,
        applyPatches: makeFakeApplyPatches(happyPatchSession()),
        composePR: fakeComposePR,
        llmClient: makeFakeLLMClient(),
      });

      expect(summary.finalExitCode).toBe(0);
      expect(fakeCheckov).not.toHaveBeenCalled();
      expect(fakeTfsec).not.toHaveBeenCalled();
      expect(fakeAws).not.toHaveBeenCalled();
      expect(fakeComposePR).toHaveBeenCalledOnce();

      const cortStage = summary.stages.find((s) => s.name === 'cort');
      expect(cortStage?.status).toBe('skipped');
      expect(cortStage?.subStages).toEqual({
        checkov: 'skipped',
        tfsec: 'skipped',
        awsContext: 'skipped',
      });

      // The empty AggregatedReport must be persisted so composePR can read it.
      const cortOnDisk = JSON.parse(
        await readFile(join(dir, 'cort-report.json'), 'utf-8'),
      ) as { findings: unknown[] };
      expect(cortOnDisk.findings).toEqual([]);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — replaying a recorded advisory file', () => {
  // The local end-to-end path (scripts/run-local.sh) runs entirely through
  // advisoriesPath, and had no coverage at all.
  const RECORDING = fileURLToPath(
    new URL('../fixtures/recorded-advisories.json', import.meta.url),
  );

  it('passes a replay fetcher to Hunter instead of the live GitHub client', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeHunter = vi.fn(
        async (opts: { outputPath: string }, fetcher?: unknown) => {
          // Prove the orchestrator supplied a fetcher, and that calling it
          // reaches the recording rather than the network.
          expect(typeof fetcher).toBe('function');
          const advisories = await (
            fetcher as (s: string, e: Ecosystem) => Promise<unknown[]>
          )('2026-07-17T17:29:23.000Z', 'NPM');
          expect(advisories).toHaveLength(21);
          await writeFile(opts.outputPath, JSON.stringify([SAMPLE_MATCH]), 'utf-8');
          return { matchCount: 1 };
        },
      );

      const summary = await orchestrate(
        baseOpts(dir, { advisoriesPath: RECORDING }),
        {
          runHunter: fakeHunter,
          applyPatches: makeFakeApplyPatches(happyPatchSession()),
          composePR: makeFakeComposePR(),
          llmClient: makeFakeLLMClient(),
        },
      );

      expect(summary.finalExitCode).toBe(0);
      expect(fakeHunter).toHaveBeenCalledOnce();
    } finally {
      await cleanup();
    }
  });

  it('fails loudly on an ecosystem mismatch rather than reporting a clean run', async () => {
    // Previously this combination filtered every node away client-side, so
    // Hunter saw 21 advisories with empty node lists, matchCount was 0, and the
    // orchestrator exited 0 with "No vulnerabilities found".
    //
    // Uses the real runHunter (no injected fake) so the failure travels the
    // production path. workingDir points at the repo root because runHunter
    // resolves the lockfile concurrently with the fetch — an unreadable
    // working dir would reject Promise.all first and mask the mismatch.
    const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
    const { dir, cleanup } = await makeTmpDir();
    try {
      const summary = await orchestrate(
        baseOpts(dir, {
          workingDir: REPO_ROOT,
          advisoriesPath: RECORDING,
          ecosystem: 'PIP' as Ecosystem,
        }),
        {
          applyPatches: makeFakeApplyPatches(happyPatchSession()),
          composePR: makeFakeComposePR(),
          llmClient: makeFakeLLMClient(),
        },
      );

      expect(summary.finalExitCode).toBe(1);
      const hunterStage = summary.stages.find((s) => s.name === 'hunter');
      expect(hunterStage?.status).toBe('failed');
      expect(hunterStage?.errorMessage).toMatch(/ecosystem mismatch/);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — stage timing captured in summary', () => {
  it('records non-negative durationMs for every stage that ran', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      // Monotonic stub clock — each call increments by 100ms.
      let t = 0;
      const now = () => {
        t += 100;
        return t;
      };

      const summary = await orchestrate(baseOpts(dir, { terraformDir: '/tf' }), {
        runHunter: makeFakeHunter([SAMPLE_MATCH]),
        runCheckov: vi.fn().mockResolvedValue(emptyCheckovReport()),
        runTfsec: vi.fn().mockResolvedValue(emptyTfsecReport()),
        runAwsContextChecks: vi.fn().mockResolvedValue(emptyAwsContextReport()),
        applyPatches: makeFakeApplyPatches(happyPatchSession()),
        composePR: makeFakeComposePR(),
        llmClient: makeFakeLLMClient(),
        now,
      });

      expect(summary.finalExitCode).toBe(0);
      for (const stage of summary.stages) {
        expect(stage.durationMs).toBeGreaterThan(0);
      }
      expect(summary.stages.map((s) => s.name)).toEqual([
        'hunter',
        'cort',
        'patcher',
        'reporter',
      ]);
    } finally {
      await cleanup();
    }
  });
});

describe('orchestrate — summary file shape', () => {
  it('persists branchName, dryRun flag, and llmTokens', async () => {
    const { dir, cleanup } = await makeTmpDir();
    try {
      const fakeLLM = makeFakeLLMClient();

      // composePR fake that actually invokes the injected llmClient so the
      // token-accumulator inside orchestrate is exercised.
      const fakeComposePR = vi.fn(async (opts: { outputPath: string }, llm?: LLMClient) => {
        if (llm) {
          await llm.complete({
            model: 'm',
            systemPrompt: 's',
            userMessage: 'u',
            maxTokens: 100,
          });
        }
        await writeFile(opts.outputPath, '## ok', 'utf-8');
        return '## ok';
      });

      const summary = await orchestrate(
        baseOpts(dir, { dryRun: false, terraformDir: '/tf' }),
        {
          runHunter: makeFakeHunter([SAMPLE_MATCH]),
          runCheckov: vi.fn().mockResolvedValue(emptyCheckovReport()),
          runTfsec: vi.fn().mockResolvedValue(emptyTfsecReport()),
          runAwsContextChecks: vi.fn().mockResolvedValue(emptyAwsContextReport()),
          applyPatches: makeFakeApplyPatches(happyPatchSession()),
          composePR: fakeComposePR,
          llmClient: fakeLLM,
        },
      );

      expect(summary.branchName).toBe('corsec/hotfix/1700000000');
      expect(summary.dryRun).toBe(false);
      // fake LLM returns 100/50 per call
      expect(summary.llmTokens).toEqual({ input: 100, output: 50 });
    } finally {
      await cleanup();
    }
  });
});
