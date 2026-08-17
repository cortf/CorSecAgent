// Orchestrator — wires Hunter → Cort → Patcher → Reporter into a single run.
//
// Design notes worth re-reading before changing this module:
//
//   1. Graceful degradation between stages. Hunter and Reporter are the only
//      stages that can abort the run (no point continuing without matches; no
//      point continuing past a malformed PR description). Every other stage's
//      failure is captured into the summary and the next stage proceeds with
//      a synthetic / empty input.
//
//   2. Injectable stage functions. The default `runStages` shape wires the
//      real implementations from Hunter / Cort / Patcher / Reporter; tests
//      override the relevant fields with mocks. This is the seam — there is
//      no other way the orchestrator's internal state is exposed.
//
//   3. Summary file is ALWAYS written before exit, including on the early-
//      abort paths (Hunter throw, Reporter throw). The workflow uploads the
//      summary as an artifact regardless of exit code.
//
//   4. No retries. Each stage runs once; failure is a final state for that
//      stage. The workflow can re-trigger the entire job if a retry is
//      desired.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { runHunter } from './hunter/run.js';
import type { Advisory, Ecosystem } from './hunter/types.js';
import { runCheckov } from './cort/runCheckov.js';
import { runTfsec } from './cort/runTfsec.js';
import { runAwsContextChecks } from './cort/awsContextChecks.js';
import { aggregateFindings } from './cort/aggregateFindings.js';
import type { AwsContextReport, CheckovReport, TfsecReport } from './cort/types.js';
import { applyPatches } from './patcher/applyPatches.js';
import type { PatchSession } from './patcher/types.js';
import { composePR } from './reporter/composePR.js';
import {
  AnthropicLLMClient,
  type LLMClient,
  type LLMCompleteOptions,
  type LLMCompleteResult,
} from './shared/llmClient.js';

// ─── stage-result types ──────────────────────────────────────────────────────

type StageStatus = 'success' | 'failed' | 'skipped';

interface StageRecord {
  name: string;
  status: StageStatus;
  durationMs: number;
  errorMessage?: string;
  // Per-scanner attribution inside the Cort stage. Populated only on the
  // Cort record so a single failed scanner is observable in the summary.
  subStages?: Record<string, StageStatus>;
}

export interface OrchestrationSummary {
  stages: StageRecord[];
  matchCount: number;
  branchName: string | null;
  llmTokens: { input: number; output: number };
  dryRun: boolean;
  outputDir: string;
  finalExitCode: number;
}

// ─── injectable stage shapes ─────────────────────────────────────────────────
//
// Each field defaults to the real implementation; tests override the ones
// they need. Keeping the shape narrow (no extra metadata, no callbacks) means
// the test doubles are trivially constructable with `vi.fn()`.

export interface OrchestrationStages {
  runHunter?: typeof runHunter;
  runCheckov?: typeof runCheckov;
  runTfsec?: typeof runTfsec;
  runAwsContextChecks?: typeof runAwsContextChecks;
  applyPatches?: typeof applyPatches;
  composePR?: typeof composePR;
  // Constructed lazily by the orchestrator when the LLM branch of the
  // Reporter is taken. Tests inject a recording fake so no real API key is
  // required and token totals are deterministic.
  llmClient?: LLMClient;
  now?: () => number;
}

export interface OrchestrateOptions {
  workingDir: string;
  outputDir: string;
  testCommand: string;
  terraformDir?: string;
  dryRun: boolean;
  ecosystem: Ecosystem;
  // Start of the advisory window. Defaults to 24 h before `now()` — the cron
  // cadence the workflow runs at. Widen it for backfills and for local testing,
  // where a 24 h window is usually empty. Note that the underlying GraphQL query
  // is capped at the 100 most recently published advisories, so widening past
  // roughly a month returns nothing extra.
  sinceISO?: string;
  // Replay a recorded advisory payload instead of querying GitHub. Makes a run
  // deterministic and removes the GITHUB_TOKEN requirement — used for local
  // end-to-end testing, never in the workflow.
  advisoriesPath?: string;
}

// Wrap a base LLMClient so the orchestrator can capture total input/output
// tokens across the run. Reporter invokes the client at most once today, but
// summing is the future-proof shape.
class TokenAccumulator implements LLMClient {
  totalInput = 0;
  totalOutput = 0;
  constructor(private readonly inner: LLMClient) {}
  async complete(opts: LLMCompleteOptions): Promise<LLMCompleteResult> {
    const r = await this.inner.complete(opts);
    this.totalInput += r.inputTokens;
    this.totalOutput += r.outputTokens;
    return r;
  }
}

// Per-scanner fallbacks. These are what a failed (or never-run) scanner
// contributes to the aggregate. There is deliberately no hand-written empty
// *AggregatedReport* to go with them: aggregating these three empty inputs
// produces it exactly, key-insertion order included, so restating the whole
// FindingCategory taxonomy here would just be a second copy to keep in sync.
function emptyCheckovReport(): CheckovReport {
  return { passed: [], failed: [], skipped: [] };
}

function emptyTfsecReport(): TfsecReport {
  return { passed: [], failed: [] };
}

function emptyAwsContextReport(): AwsContextReport {
  return {
    alb: { albCount: 0, albArns: [] },
    imdsv2: { checked: [], compliantCount: 0, nonCompliantCount: 0 },
  };
}

function synthEmptyPatchSession(branchName: string, errorMessage: string): PatchSession {
  return {
    branchName,
    results: [],
    summary: {
      attempted: 0,
      succeeded: 0,
      failedTests: 0,
      failedInstall: 0,
      noFixAvailable: 0,
    },
  };
  // errorMessage is intentionally NOT placed on a PatchSession field — the
  // type has no slot for one. We surface the underlying error via the stage
  // record's errorMessage; that's what the workflow / summary look at.
  // (Kept the parameter so callers can document intent at the call site.)
  void errorMessage;
}

// Build a drop-in replacement for `fetchRecentAdvisories` that reads a recorded
// payload off disk. The file holds the same `Advisory[]` shape the GraphQL query
// returns, so a recording captured from the live API replays exactly.
//
// The ecosystem filter is applied here because the live query filters
// server-side (`vulnerabilities(ecosystem: $ecosystem)`); without it a mixed
// recording would surface PIP packages during an NPM run. `sinceISO` is ignored
// — the recording is already a point-in-time snapshot.
function fileAdvisoryFetcher(
  path: string,
): (sinceISO: string, ecosystem: Ecosystem) => Promise<Advisory[]> {
  return async (_sinceISO, ecosystem) => {
    let raw: string;
    try {
      raw = await readFile(path, 'utf-8');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`orchestrate: cannot read advisories file ${path}: ${msg}`);
    }
    let all: Advisory[];
    try {
      all = JSON.parse(raw) as Advisory[];
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`orchestrate: malformed JSON in advisories file ${path}: ${msg}`);
    }
    return all.map((advisory) => ({
      ...advisory,
      vulnerabilities: {
        nodes: advisory.vulnerabilities.nodes.filter(
          (node) => node.package.ecosystem === ecosystem,
        ),
      },
    }));
  };
}

function stageLog(name: string, phase: 'started' | 'complete', durationMs?: number): void {
  // Workflow's job summary parses these lines. Format must remain stable.
  if (phase === 'started') {
    // eslint-disable-next-line no-console
    console.log(`[stage:${name}] started`);
  } else {
    // eslint-disable-next-line no-console
    console.log(`[stage:${name}] complete duration=${durationMs ?? 0}ms`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main orchestrator. Returns the summary record (also persisted to disk) so
// the CLI wrapper can pick the exit code.
// ─────────────────────────────────────────────────────────────────────────────

export async function orchestrate(
  opts: OrchestrateOptions,
  stages: OrchestrationStages = {},
): Promise<OrchestrationSummary> {
  const _runHunter = stages.runHunter ?? runHunter;
  const _runCheckov = stages.runCheckov ?? runCheckov;
  const _runTfsec = stages.runTfsec ?? runTfsec;
  const _runAwsContextChecks = stages.runAwsContextChecks ?? runAwsContextChecks;
  const _applyPatches = stages.applyPatches ?? applyPatches;
  const _composePR = stages.composePR ?? composePR;
  const now = stages.now ?? Date.now;

  await mkdir(opts.outputDir, { recursive: true });

  const hunterPath = join(opts.outputDir, 'hunter-matches.json');
  const cortPath = join(opts.outputDir, 'cort-report.json');
  const patchPath = join(opts.outputDir, 'patch-session.json');
  const prPath = join(opts.outputDir, 'pr-description.md');
  const summaryPath = join(opts.outputDir, 'orchestration-summary.json');

  const stageRecords: StageRecord[] = [];
  let matchCount = 0;
  let branchName: string | null = null;
  const tokens = { input: 0, output: 0 };

  const writeSummary = async (finalExitCode: number): Promise<OrchestrationSummary> => {
    const summary: OrchestrationSummary = {
      stages: stageRecords,
      matchCount,
      branchName,
      llmTokens: tokens,
      dryRun: opts.dryRun,
      outputDir: opts.outputDir,
      finalExitCode,
    };
    await writeFile(summaryPath, JSON.stringify(summary, null, 2), 'utf-8');
    return summary;
  };

  // ─── Hunter ────────────────────────────────────────────────────────────────
  stageLog('hunter', 'started');
  const hunterStart = now();
  try {
    const result = await _runHunter(
      {
        sinceISO: opts.sinceISO ?? new Date(now() - 24 * 60 * 60 * 1000).toISOString(),
        ecosystem: opts.ecosystem,
        packageJsonPath: join(opts.workingDir, 'package.json'),
        lockfilePath: join(opts.workingDir, 'package-lock.json'),
        outputPath: hunterPath,
      },
      // undefined falls through to runHunter's default (the live GitHub client).
      opts.advisoriesPath ? fileAdvisoryFetcher(opts.advisoriesPath) : undefined,
    );
    matchCount = result.matchCount;
    const duration = now() - hunterStart;
    stageRecords.push({ name: 'hunter', status: 'success', durationMs: duration });
    stageLog('hunter', 'complete', duration);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const duration = now() - hunterStart;
    stageRecords.push({
      name: 'hunter',
      status: 'failed',
      durationMs: duration,
      errorMessage: msg,
    });
    stageLog('hunter', 'complete', duration);
    // eslint-disable-next-line no-console
    console.error(`[orchestrate] hunter failed: ${msg}`);
    return writeSummary(1);
  }

  if (matchCount === 0) {
    // eslint-disable-next-line no-console
    console.log('[orchestrate] No vulnerabilities found — exiting successfully.');
    return writeSummary(0);
  }

  // ─── Cort ──────────────────────────────────────────────────────────────────
  stageLog('cort', 'started');
  const cortStart = now();

  // No terraform-dir: every sub-stage stays 'skipped' and the three empty
  // scanner reports flow into the aggregator unchanged. Reporter still runs
  // against the result and will pick template mode (no findings, zero
  // non-compliant, zero ALBs — an empty account is a wash), so no LLM call.
  let checkov = emptyCheckovReport();
  let tfsec = emptyTfsecReport();
  let aws = emptyAwsContextReport();
  let cortOverall: StageStatus = 'skipped';
  const cortSubStages: Record<string, StageStatus> = {
    checkov: 'skipped',
    tfsec: 'skipped',
    awsContext: 'skipped',
  };

  if (opts.terraformDir) {
    const [checkovRes, tfsecRes, awsRes] = await Promise.allSettled([
      _runCheckov(opts.terraformDir),
      _runTfsec(opts.terraformDir),
      _runAwsContextChecks(),
    ]);

    // One decision per scanner instead of three. Value, status and error log
    // now come out of a single branch, so a 'success' sub-stage sitting beside
    // a fallback empty report is no longer representable.
    const checkovSettled = settle(checkovRes, emptyCheckovReport, 'checkov');
    const tfsecSettled = settle(tfsecRes, emptyTfsecReport, 'tfsec');
    const awsSettled = settle(awsRes, emptyAwsContextReport, 'aws-context');

    checkov = checkovSettled.value;
    tfsec = tfsecSettled.value;
    aws = awsSettled.value;

    cortSubStages['checkov'] = checkovSettled.status;
    cortSubStages['tfsec'] = tfsecSettled.status;
    cortSubStages['awsContext'] = awsSettled.status;

    // Rollup computed from the three results in hand rather than by re-scanning
    // the stringly-keyed sub-stage record.
    cortOverall = [checkovSettled, tfsecSettled, awsSettled].every(
      (s) => s.status === 'failed',
    )
      ? 'failed'
      : 'success';
  }

  const cortReport = aggregateFindings(checkov, tfsec, aws);
  await writeFile(cortPath, JSON.stringify(cortReport, null, 2), 'utf-8');
  const cortDuration = now() - cortStart;
  stageRecords.push({
    name: 'cort',
    status: cortOverall,
    durationMs: cortDuration,
    subStages: cortSubStages,
  });
  stageLog('cort', 'complete', cortDuration);

  // ─── Patcher ───────────────────────────────────────────────────────────────
  stageLog('patcher', 'started');
  const patcherStart = now();
  let patchSession: PatchSession | null = null;
  try {
    patchSession = await _applyPatches({
      matchesPath: hunterPath,
      outputPath: patchPath,
      workingDir: opts.workingDir,
      testCommand: opts.testCommand,
    });
    branchName = patchSession.branchName;
    const duration = now() - patcherStart;
    stageRecords.push({ name: 'patcher', status: 'success', durationMs: duration });
    stageLog('patcher', 'complete', duration);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const synthBranch = `corsec/hotfix/${Math.floor(now() / 1000)}`;
    patchSession = synthEmptyPatchSession(synthBranch, msg);
    branchName = patchSession.branchName;
    // Persist the synthetic session so the Reporter can still read it from
    // disk via composePR's existing path-based interface.
    await writeFile(patchPath, JSON.stringify(patchSession, null, 2), 'utf-8');
    const duration = now() - patcherStart;
    stageRecords.push({
      name: 'patcher',
      status: 'failed',
      durationMs: duration,
      errorMessage: msg,
    });
    stageLog('patcher', 'complete', duration);
    // eslint-disable-next-line no-console
    console.error(`[orchestrate] patcher failed: ${msg}`);
  }

  // ─── Reporter ──────────────────────────────────────────────────────────────
  stageLog('reporter', 'started');
  const reporterStart = now();

  // Wrap whatever LLM client was injected (or the real Anthropic client)
  // so we can read input/output totals for the summary. Construct lazily so
  // missing ANTHROPIC_API_KEY only errors if the LLM branch is actually
  // taken — which we cannot know without composePR's mode-decision running.
  let accumulator: TokenAccumulator | null = null;
  const llmClientForReporter: LLMClient | undefined = (() => {
    if (stages.llmClient) {
      accumulator = new TokenAccumulator(stages.llmClient);
      return accumulator;
    }
    try {
      accumulator = new TokenAccumulator(new AnthropicLLMClient());
      return accumulator;
    } catch {
      // No API key — composePR may still succeed via template mode. Pass
      // undefined so composePR's default-construction path runs (and throws
      // only if the LLM branch is actually entered).
      accumulator = null;
      return undefined;
    }
  })();

  try {
    await _composePR(
      {
        matchesPath: hunterPath,
        cortReportPath: cortPath,
        patchSessionPath: patchPath,
        outputPath: prPath,
      },
      llmClientForReporter,
    );
    if (accumulator) {
      tokens.input = accumulator.totalInput;
      tokens.output = accumulator.totalOutput;
    }
    const duration = now() - reporterStart;
    stageRecords.push({ name: 'reporter', status: 'success', durationMs: duration });
    stageLog('reporter', 'complete', duration);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (accumulator) {
      tokens.input = accumulator.totalInput;
      tokens.output = accumulator.totalOutput;
    }
    const duration = now() - reporterStart;
    stageRecords.push({
      name: 'reporter',
      status: 'failed',
      durationMs: duration,
      errorMessage: msg,
    });
    stageLog('reporter', 'complete', duration);
    // eslint-disable-next-line no-console
    console.error(`[orchestrate] reporter failed: ${msg}`);
    return writeSummary(1);
  }

  return writeSummary(0);
}

function stringifyErr(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

// Collapse one settled scanner result into the only two things the Cort stage
// needs from it — the value to aggregate and the status to report — plus the
// error log. Producing all three from a single branch is what keeps them from
// disagreeing.
//
// `label` is passed explicitly rather than derived from the sub-stage key
// because the two differ: the AWS check is keyed 'awsContext' but has always
// logged as 'aws-context', and that operator-facing string should not change
// as a side effect of this refactor.
function settle<T>(
  result: PromiseSettledResult<T>,
  fallback: () => T,
  label: string,
): { value: T; status: StageStatus } {
  if (result.status === 'fulfilled') {
    return { value: result.value, status: 'success' };
  }
  // eslint-disable-next-line no-console
  console.error(`[orchestrate] ${label} failed: ${stringifyErr(result.reason)}`);
  return { value: fallback(), status: 'failed' };
}

function isEcosystem(s: string): s is Ecosystem {
  return s === 'NPM' || s === 'PIP' || s === 'MAVEN';
}

// ─── CLI entry point ─────────────────────────────────────────────────────────
// Guarded so importing this module from tests does not start a CLI run.

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({
    options: {
      'working-dir': { type: 'string' },
      'output-dir': { type: 'string' },
      'test-command': { type: 'string' },
      'terraform-dir': { type: 'string' },
      'dry-run': { type: 'boolean' },
      ecosystem: { type: 'string' },
      since: { type: 'string' },
      'advisories-file': { type: 'string' },
    },
    strict: true,
  });

  const outputDir = values['output-dir'];
  if (!outputDir) {
    // eslint-disable-next-line no-console
    console.error('Error: --output-dir <path> is required');
    process.exit(1);
  }

  const ecosystemRaw = values.ecosystem ?? 'NPM';
  if (!isEcosystem(ecosystemRaw)) {
    // eslint-disable-next-line no-console
    console.error('Error: --ecosystem must be one of NPM, PIP, MAVEN');
    process.exit(1);
  }

  // An empty --terraform-dir from a shell `${{ inputs.terraform_dir || '' }}`
  // expansion should be treated as "not provided" — otherwise we'd run Cort
  // against the empty string and fail the directory pre-flight.
  const terraformDirRaw = values['terraform-dir'];
  const hasTerraformDir = terraformDirRaw !== undefined && terraformDirRaw.length > 0;

  // Same empty-string guard as --terraform-dir: a workflow expansion that
  // resolves to "" must read as "not provided", not as an empty path/date.
  const sinceRaw = values.since;
  const hasSince = sinceRaw !== undefined && sinceRaw.length > 0;
  const advisoriesRaw = values['advisories-file'];
  const hasAdvisories = advisoriesRaw !== undefined && advisoriesRaw.length > 0;

  const orchestrateOpts: OrchestrateOptions = {
    workingDir: values['working-dir'] ?? '.',
    outputDir,
    testCommand: values['test-command'] ?? 'npm test',
    dryRun: values['dry-run'] === true,
    ecosystem: ecosystemRaw,
    // Only set optional fields when actually provided — exactOptionalPropertyTypes
    // distinguishes "field absent" from "field present and undefined".
    ...(hasTerraformDir ? { terraformDir: terraformDirRaw } : {}),
    ...(hasSince ? { sinceISO: sinceRaw } : {}),
    ...(hasAdvisories ? { advisoriesPath: advisoriesRaw } : {}),
  };

  orchestrate(orchestrateOpts)
    .then((summary) => {
      process.exit(summary.finalExitCode);
    })
    .catch((err: unknown) => {
      // eslint-disable-next-line no-console
      console.error(
        'orchestrate failed unexpectedly:',
        err instanceof Error ? err.message : String(err),
      );
      process.exit(1);
    });
}
