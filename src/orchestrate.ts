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

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { runHunter } from './hunter/run.js';
import { fileAdvisoryFetcher } from './hunter/advisorySource.js';
// types.ts is no longer type-only: ECOSYSTEMS and isEcosystem are values.
import { ECOSYSTEMS, isEcosystem } from './hunter/types.js';
import type { Ecosystem } from './hunter/types.js';
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

// Discriminated on `status` so the message and the outcome cannot disagree.
// The previous flat shape allowed {status:'success', errorMessage:'boom'} and,
// more importantly, {status:'failed'} with NO errorMessage — nothing forced it
// on, and three hand-written catch blocks were the only thing supplying it. The
// operator-facing jq table in corsec-pipeline.yml renders these records
// directly, so a failed stage with no message is a real hole.
//
// `subStages` stays optional on every arm: it is populated only by Cort, whose
// own status can be any of the three.
type StageRecord =
  | {
      name: string;
      status: 'success' | 'skipped';
      durationMs: number;
      subStages?: Record<string, StageStatus>;
    }
  | {
      name: string;
      status: 'failed';
      durationMs: number;
      // Required, not optional — that is the point of the split.
      errorMessage: string;
      subStages?: Record<string, StageStatus>;
    };

export interface OrchestrationSummary {
  stages: StageRecord[];
  matchCount: number;
  branchName: string | null;
  llmTokens: { input: number; output: number };
  // Records what the operator ASKED for; it does not enforce anything.
  //
  // Named for that role deliberately. `dryRun` read as the safety control that
  // prevents pushes, and it is not: --dry-run is never branched on anywhere in
  // src/, no stage receives it, and applyPatches has no dry-run parameter and
  // never pushes by design. The actual gate lives in the workflow, which reads
  // its own resolved input rather than this field. Keeping the flag (README and
  // scripts/run-local.sh both pass it) but naming it honestly.
  dryRunRequested: boolean;
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
  return { alb: { albArns: [] }, imdsv2: { checked: [] } };
}

// Stand-in session persisted when the Patcher throws, so the Reporter can still
// read a well-formed patch-session.json off disk.
//
// It takes no error message: PatchSession has no slot for one, and the previous
// signature accepted the message only to discard it with `void`. The underlying
// error is recorded on the patcher stage record, which is what the workflow's
// job summary actually reads.
function synthEmptyPatchSession(branchName: string): PatchSession {
  return {
    branchName,
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
  };
}

// Human-readable progress markers for the CI log. Nothing parses these.
//
// This used to claim "Workflow's job summary parses these lines. Format must
// remain stable." It does not: grep over .github/workflows/ finds zero
// references to `stage:`, and the job summary reads orchestration-summary.json
// with jq without ever touching stdout. The comment imposed a format-stability
// constraint that did not exist. The machine-readable contract is the summary
// artifact; that is the thing to keep stable.
function stageLog(name: string, phase: 'started' | 'complete', durationMs?: number): void {
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

  // --since and --advisories-file are both representable together and the
  // combination is meaningless: a recording is a point-in-time snapshot with its
  // own window. Warned here rather than inside the fetcher, because this is the
  // only place that can distinguish an explicitly-passed --since from the 24h
  // default computed below — warning on the default would fire on every local
  // replay run and train the reader to ignore it.
  if (opts.advisoriesPath !== undefined && opts.sinceISO !== undefined) {
    // eslint-disable-next-line no-console
    console.warn(
      '[orchestrate] --since is ignored when --advisories-file is set; the ' +
        'recording carries its own window.',
    );
  }

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

  // Push a record and emit its completion log from ONE captured duration.
  //
  // Reusing the same number for both is load-bearing rather than tidy: the test
  // clock stub advances 100ms on every call, so calling now() a second time to
  // build the log line would double the recorded duration for every stage.
  const recordStage = (record: StageRecord): void => {
    stageRecords.push(record);
    stageLog(record.name, 'complete', record.durationMs);
  };

  // The three throwing stages (hunter, patcher, reporter) share the whole
  // log-start / capture-start / compute-duration / push-record / log-complete
  // ritual and differ only in their degradation *policy* — which is the thing
  // worth reading, and was previously buried in near-textual copies of that
  // boilerplate.
  //
  // Returns an outcome value rather than rethrowing, so each call site states
  // its policy in the open. Cort deliberately does not use this: it never
  // throws (its status is derived from three settled sub-results), so it keeps
  // a bespoke path over the shared recordStage primitive. One helper honestly
  // does not fit all four.
  const runStage = async <T>(
    name: string,
    fn: () => Promise<T>,
  ): Promise<{ ok: true; value: T } | { ok: false; error: string }> => {
    stageLog(name, 'started');
    const start = now();
    try {
      const value = await fn();
      recordStage({ name, status: 'success', durationMs: now() - start });
      return { ok: true, value };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      recordStage({ name, status: 'failed', durationMs: now() - start, errorMessage: error });
      // eslint-disable-next-line no-console
      console.error(`[orchestrate] ${name} failed: ${error}`);
      return { ok: false, error };
    }
  };

  const writeSummary = async (finalExitCode: number): Promise<OrchestrationSummary> => {
    const summary: OrchestrationSummary = {
      stages: stageRecords,
      matchCount,
      branchName,
      llmTokens: tokens,
      dryRunRequested: opts.dryRun,
      outputDir: opts.outputDir,
      finalExitCode,
    };
    await writeFile(summaryPath, JSON.stringify(summary, null, 2), 'utf-8');
    return summary;
  };

  // ─── Hunter ────────────────────────────────────────────────────────────────
  // Policy: abort. There is no point continuing without matches.
  const hunter = await runStage('hunter', () =>
    _runHunter(
      {
        sinceISO: opts.sinceISO ?? new Date(now() - 24 * 60 * 60 * 1000).toISOString(),
        ecosystem: opts.ecosystem,
        packageJsonPath: join(opts.workingDir, 'package.json'),
        lockfilePath: join(opts.workingDir, 'package-lock.json'),
        outputPath: hunterPath,
      },
      // undefined falls through to runHunter's default (the live GitHub client).
      opts.advisoriesPath ? fileAdvisoryFetcher(opts.advisoriesPath) : undefined,
    ),
  );
  if (!hunter.ok) return writeSummary(1);
  matchCount = hunter.value.matchCount;

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
  // Cort's status is derived from three settled sub-results rather than thrown,
  // so it is tracked as a small tagged value instead of going through runStage.
  // Modelling it this way means the 'failed' case cannot be recorded without
  // the message that explains it.
  let cortOutcome:
    | { status: 'success' | 'skipped' }
    | { status: 'failed'; errorMessage: string } = { status: 'skipped' };
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
    // the stringly-keyed sub-stage record. Partial failure is still 'success':
    // the surviving scanners' findings are real and the aggregate is usable.
    const settled = [checkovSettled, tfsecSettled, awsSettled];
    const errors = settled.map((s) => s.error).filter((e): e is string => e !== null);
    cortOutcome =
      errors.length === settled.length
        ? { status: 'failed', errorMessage: `every Cort scanner failed — ${errors.join('; ')}` }
        : { status: 'success' };
  }

  const cortReport = aggregateFindings(checkov, tfsec, aws);
  await writeFile(cortPath, JSON.stringify(cortReport, null, 2), 'utf-8');
  const cortDuration = now() - cortStart;
  recordStage(
    cortOutcome.status === 'failed'
      ? {
          name: 'cort',
          status: 'failed',
          durationMs: cortDuration,
          errorMessage: cortOutcome.errorMessage,
          subStages: cortSubStages,
        }
      : {
          name: 'cort',
          status: cortOutcome.status,
          durationMs: cortDuration,
          subStages: cortSubStages,
        },
  );

  // ─── Patcher ───────────────────────────────────────────────────────────────
  // Policy: degrade. Substitute a synthetic empty session and carry on, so the
  // Reporter still produces a document describing the run.
  const patcher = await runStage('patcher', () =>
    _applyPatches({
      matchesPath: hunterPath,
      outputPath: patchPath,
      workingDir: opts.workingDir,
      testCommand: opts.testCommand,
    }),
  );
  if (patcher.ok) {
    branchName = patcher.value.branchName;
  } else {
    const patchSession = synthEmptyPatchSession(`corsec/hotfix/${Math.floor(now() / 1000)}`);
    branchName = patchSession.branchName;
    // Persist the synthetic session so the Reporter can still read it from
    // disk via composePR's existing path-based interface.
    await writeFile(patchPath, JSON.stringify(patchSession, null, 2), 'utf-8');
  }

  // ─── Reporter ──────────────────────────────────────────────────────────────
  //
  // Wrap whatever LLM client is available so the run's input/output token
  // totals land in the summary. "Is the LLM available" is answered once, here,
  // as a value: tryCreate returns null when ANTHROPIC_API_KEY is unset rather
  // than throwing an error we would then catch purely for control flow.
  // composePR may still succeed in template mode without a client, and will
  // raise its own error if the LLM branch is actually entered.
  const baseClient = stages.llmClient ?? AnthropicLLMClient.tryCreate();
  const accumulator = baseClient === null ? null : new TokenAccumulator(baseClient);

  // Policy: abort. There is no point carrying on past a malformed PR description.
  const reporter = await runStage('reporter', () =>
    _composePR(
      {
        matchesPath: hunterPath,
        cortReportPath: cortPath,
        patchSessionPath: patchPath,
        outputPath: prPath,
      },
      accumulator ?? undefined,
    ),
  );

  // Read the totals on both paths — a Reporter that threw may still have spent
  // tokens before doing so, and an unreported cost is the one we most want to
  // see in the summary.
  if (accumulator) {
    tokens.input = accumulator.totalInput;
    tokens.output = accumulator.totalOutput;
  }

  return writeSummary(reporter.ok ? 0 : 1);
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
): { value: T; status: StageStatus; error: string | null } {
  if (result.status === 'fulfilled') {
    return { value: result.value, status: 'success', error: null };
  }
  const error = stringifyErr(result.reason);
  // eslint-disable-next-line no-console
  console.error(`[orchestrate] ${label} failed: ${error}`);
  // The message is carried, not just logged: when all three scanners fail the
  // Cort stage record needs an errorMessage, and stdout is not readable from
  // the summary artifact the workflow's job summary renders.
  return { value: fallback(), status: 'failed', error: `${label}: ${error}` };
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
    console.error(`Error: --ecosystem must be one of ${ECOSYSTEMS.join(', ')}`);
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
