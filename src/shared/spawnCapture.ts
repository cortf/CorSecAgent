// The single spawn-and-capture primitive.
//
// Four hand-rolled copies of this mechanic previously lived in runCheckov,
// runTfsec and applyPatches (twice). They had already drifted — three of the
// four translated ENOENT into an actionable install hint and the fourth did
// not — and all four shared one latent defect: `exitCode: code ?? 0` reports a
// signal-killed child as a clean exit 0. See `exitCode` below for the fix.
//
// None of the callers' default executors are exercised by their own unit tests
// (every test injects an executor), which is exactly why the copies were free
// to drift. This module has its own test that drives the real helper against
// `process.execPath -e`, so the behaviour is pinned in one place.

import { spawn } from 'node:child_process';
import { constants } from 'node:os';

export interface CapturedProcess {
  stdout: string;
  stderr: string;
  // Never 0 for a child that did not exit on its own terms. A child terminated
  // by a signal reports `code === null` on the 'close' event; the shell
  // convention of 128 + signal number is synthesised in its place so that every
  // caller's existing `exitCode !== 0` check treats a kill as the failure it
  // is. SIGKILL → 137, SIGTERM → 143.
  //
  // This matters most for the patcher's shared test run: an OOM-killed or
  // CI-timeout-killed suite used to resolve as exit 0, which assigned every
  // installed package `patched-tests-passed` — the exact token the workflow's
  // PR gate counts — and opened a PR whose body asserted "All tests passing"
  // for a suite that was killed.
  exitCode: number;
  // The terminating signal name, or null for a normal exit. Callers that want
  // to distinguish "the suite failed" from "the suite was killed" read this;
  // callers that only branch on exitCode keep working unchanged.
  signal: NodeJS.Signals | null;
}

export interface SpawnCaptureOptions {
  cwd?: string;
  // Run the command through a shell. Used for user-supplied test commands,
  // which arrive as a single verbatim string ("npm run test:integration --
  // --bail") that we must not attempt to parse into argv.
  shell?: boolean;
  // Replaces the raw ENOENT error with an actionable install hint. Omit to let
  // the underlying error propagate. Note this never fires under `shell: true` —
  // a missing binary is then the shell's problem and surfaces as exit 127.
  notFoundMessage?: string;
}

export function spawnCapture(
  command: string,
  args: string[],
  options: SpawnCaptureOptions = {},
): Promise<CapturedProcess> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
      ...(options.shell === true ? { shell: true } : {}),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout?.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    child.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ENOENT' && options.notFoundMessage !== undefined) {
        reject(new Error(options.notFoundMessage));
        return;
      }
      reject(err);
    });

    child.on('close', (code, signal) => {
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
        exitCode: exitCodeFor(code, signal),
        signal,
      });
    });
  });
}

// Node reports exactly one of (code, signal) as non-null on 'close'. The old
// `code ?? 0` collapsed the signal case into success; this maps it to the
// conventional 128+N instead. An unrecognised signal name still yields 128,
// which is non-zero — the property every caller actually depends on.
function exitCodeFor(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  if (signal !== null) {
    const signals: Record<string, number> = constants.signals;
    return 128 + (signals[signal] ?? 0);
  }
  // Neither code nor signal — not a shape Node documents. Fail loudly rather
  // than inventing a clean exit.
  return 128;
}
