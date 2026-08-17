import { stat } from 'node:fs/promises';
import { spawnCapture } from '../shared/spawnCapture.js';
import type { CheckSeverity, CheckovFinding, CheckovReport } from './types.js';

// Minimal callable interface for invoking the Checkov CLI.
// Tests inject a fake executor so the suite never has to actually spawn checkov
// (which would couple CI to a Python install). The default executor below is
// the only path that touches child_process.
export type CheckovExecutor = (
  args: string[],
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

// Raw shapes of Checkov's JSON output. Grounded in:
// https://www.checkov.io/8.Outputs/JSON.html
//
// These are intentionally permissive (most fields optional) because Checkov's
// output is wide and we only consume a small slice. Anything we don't read is
// allowed to be missing or any shape — we only narrow the fields runCheckov
// actually projects into CheckovFinding.
interface RawCheck {
  check_id?: string;
  check_name?: string;
  check_result?: { result?: string };
  file_path?: string;
  file_line_range?: [number, number];
  resource?: string;
  severity?: string | null;
  guideline?: string | null;
}

interface RawCheckovOutput {
  results?: {
    passed_checks?: RawCheck[];
    failed_checks?: RawCheck[];
    skipped_checks?: RawCheck[];
  };
}

const CHECKOV_ARGS = (directory: string): string[] => [
  '-d',
  directory,
  '--framework',
  'terraform',
  '--output',
  'json',
  // --soft-fail makes Checkov exit 0 even when findings exist. We want the
  // findings as data, not a non-zero exit code that would mask real errors
  // (missing directory, parsing failure, etc.) further down the pipeline.
  '--soft-fail',
];

export async function runCheckov(
  directory: string,
  executor: CheckovExecutor = defaultExecutor,
): Promise<CheckovReport> {
  // Pre-flight the directory ourselves so the error names the offending path
  // directly instead of relying on Checkov's stderr formatting.
  try {
    const s = await stat(directory);
    if (!s.isDirectory()) {
      throw new Error(`runCheckov: ${directory} exists but is not a directory`);
    }
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'ENOENT') {
      throw new Error(`runCheckov: directory does not exist: ${directory}`);
    }
    throw err;
  }

  const { stdout, stderr, exitCode } = await executor(CHECKOV_ARGS(directory));

  if (exitCode !== 0) {
    throw new Error(
      `runCheckov: checkov exited with code ${exitCode} for directory ${directory}: ${stderr.trim()}`,
    );
  }

  let raw: RawCheckovOutput;
  try {
    raw = JSON.parse(stdout) as RawCheckovOutput;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`runCheckov: failed to parse checkov stdout as JSON for ${directory}: ${msg}`);
  }

  // Membership in these three arrays IS the partition — Checkov has already
  // done it, and we do not second-guess it from each row's `check_result`
  // string. (We used to project that string onto every finding, which meant an
  // unrecognised value produced a row marked FAILED sitting inside `passed`.)
  return {
    passed: (raw.results?.passed_checks ?? []).map(toFinding),
    failed: (raw.results?.failed_checks ?? []).map(toFinding),
    skipped: (raw.results?.skipped_checks ?? []).map(toFinding),
  };
}

function toFinding(c: RawCheck): CheckovFinding {
  return {
    checkId: c.check_id ?? '',
    checkName: c.check_name ?? '',
    severity: normaliseSeverity(c.severity ?? null),
    filePath: c.file_path ?? '',
    fileLineRange: c.file_line_range ?? [0, 0],
    resource: c.resource ?? '',
    guideline: c.guideline ?? null,
  };
}

function normaliseSeverity(raw: string | null): CheckSeverity | null {
  if (raw === null) return null;
  const upper = raw.toUpperCase();
  if (upper === 'LOW' || upper === 'MEDIUM' || upper === 'HIGH' || upper === 'CRITICAL') {
    return upper;
  }
  return null;
}

// Default executor: spawns the checkov binary and resolves with the captured
// streams once the child exits. ENOENT is intercepted and rethrown with a
// concrete install hint, since "spawn checkov ENOENT" alone is not actionable
// for a first-time user.
const defaultExecutor: CheckovExecutor = (args) =>
  spawnCapture('checkov', args, {
    notFoundMessage:
      "runCheckov: 'checkov' binary not found on PATH. Install it with `pip install checkov` (or `pipx install checkov`).",
  });
