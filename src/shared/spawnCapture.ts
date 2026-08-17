// The single spawn-and-capture primitive.
//
// Four hand-rolled copies of this mechanic previously lived in runCheckov,
// runTfsec and applyPatches (twice). They had already drifted — three of the
// four translated ENOENT into an actionable install hint and the fourth did
// not.
//
// None of the callers' default executors are exercised by their own unit tests
// (every test injects an executor), which is exactly why the copies were free
// to drift. This module has its own test that drives the real helper against
// `process.execPath -e`, so the behaviour is pinned in one place.

import { spawn } from 'node:child_process';

export interface CapturedProcess {
  stdout: string;
  stderr: string;
  exitCode: number;
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

    child.on('close', (code) => {
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
        exitCode: code ?? 0,
      });
    });
  });
}
