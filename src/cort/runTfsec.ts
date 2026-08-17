import { stat } from 'node:fs/promises';
import { spawnCapture } from '../shared/spawnCapture.js';
import type { TfsecFinding, TfsecReport, TfsecSeverity } from './types.js';

// Minimal callable interface for invoking the tfsec CLI.
// Tests inject a fake executor so the suite never has to actually spawn tfsec
// (which would couple CI to a Go-binary install). The default executor below
// is the only path that touches child_process.
export type TfsecExecutor = (
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

// Raw shapes of tfsec's JSON output. Grounded in tfsec's `Result` struct and
// JSON formatter: https://github.com/aquasecurity/tfsec
//
// Permissive on purpose — tfsec's payload carries many fields we don't read
// (links, impact, rule_provider, etc.) and we only narrow the ones runTfsec
// actually projects into TfsecFinding.
//
// `status` is an integer: 0 = failed, 1 = passed, 2 = ignored. See tfsec's
// pkg/scan/result.go for the enum.
interface RawTfsecResult {
  rule_id?: string;
  rule_description?: string;
  severity?: string;
  status?: number;
  resource?: string;
  resolution?: string | null;
  location?: {
    filename?: string;
    start_line?: number;
    end_line?: number;
  };
}

interface RawTfsecOutput {
  results?: RawTfsecResult[];
}

// tfsec accepts the target directory as a positional argument — NOT behind a
// -d flag (this is a real behavioural difference from Checkov). The other
// flags match Checkov's wrapper in intent: emit JSON and don't propagate
// findings into the exit code.
const TFSEC_ARGS = (directory: string): string[] => [
  directory,
  '--format',
  'json',
  // --soft-fail makes tfsec exit 0 even when findings exist. We want findings
  // as data, not a non-zero exit code that would mask real failures (missing
  // directory, parse error, etc.) further down the pipeline.
  '--soft-fail',
];

export async function runTfsec(
  directory: string,
  executor: TfsecExecutor = defaultExecutor,
): Promise<TfsecReport> {
  // Pre-flight the directory ourselves so the error names the offending path
  // directly instead of relying on tfsec's stderr formatting.
  try {
    const s = await stat(directory);
    if (!s.isDirectory()) {
      throw new Error(`runTfsec: ${directory} exists but is not a directory`);
    }
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'ENOENT') {
      throw new Error(`runTfsec: directory does not exist: ${directory}`);
    }
    throw err;
  }

  const { stdout, stderr, exitCode } = await executor(TFSEC_ARGS(directory));

  if (exitCode !== 0) {
    throw new Error(
      `runTfsec: tfsec exited with code ${exitCode} for directory ${directory}: ${stderr.trim()}`,
    );
  }

  let raw: RawTfsecOutput;
  try {
    raw = JSON.parse(stdout) as RawTfsecOutput;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`runTfsec: failed to parse tfsec stdout as JSON for ${directory}: ${msg}`);
  }

  const all = (raw.results ?? []).map(toFinding);
  const passed = all.filter((f) => f.status === 'passed');
  const failed = all.filter((f) => f.status === 'failed');

  return {
    passed,
    failed,
    summary: {
      passed: passed.length,
      failed: failed.length,
    },
  };
}

function toFinding(r: RawTfsecResult): TfsecFinding {
  return {
    ruleId: r.rule_id ?? '',
    ruleDescription: r.rule_description ?? '',
    severity: normaliseSeverity(r.severity),
    status: normaliseStatus(r.status),
    filePath: r.location?.filename ?? '',
    lineRange: [r.location?.start_line ?? 0, r.location?.end_line ?? 0],
    resource: r.resource ?? '',
    resolution: r.resolution ?? null,
  };
}

function normaliseStatus(raw: number | undefined): 'passed' | 'failed' {
  // tfsec status enum (pkg/scan/result.go): 0 = failed, 1 = passed, 2 = ignored.
  // Anything-not-passed collapses to 'failed' so an unexpected ignored / new
  // status surfaces rather than being silently dropped.
  return raw === 1 ? 'passed' : 'failed';
}

function normaliseSeverity(raw: string | undefined): TfsecSeverity {
  const upper = (raw ?? '').toUpperCase();
  if (upper === 'LOW' || upper === 'MEDIUM' || upper === 'HIGH' || upper === 'CRITICAL') {
    return upper;
  }
  // tfsec always ships a severity on built-in rules, so an unknown value is a
  // schema surprise rather than a missing field. Default to MEDIUM to keep the
  // finding visible without escalating it into the loudest bucket.
  return 'MEDIUM';
}

// Default executor: spawns the tfsec binary and resolves with the captured
// streams once the child exits. ENOENT is intercepted and rethrown with an
// install pointer — tfsec's installation varies by platform (brew, go install,
// binary download, container) so we point at the project README rather than
// prescribing one command.
const defaultExecutor: TfsecExecutor = (args) =>
  spawnCapture('tfsec', args, {
    notFoundMessage:
      "runTfsec: 'tfsec' binary not found on PATH. Install instructions vary by platform — see https://github.com/aquasecurity/tfsec",
  });
