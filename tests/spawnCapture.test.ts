import { describe, it, expect } from 'vitest';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';
import { spawnCapture } from '../src/shared/spawnCapture.js';

// Unlike every other test in this suite, these drive the REAL helper rather
// than an injected executor — spawning `process.execPath -e '<script>'`, which
// needs no fixture binary and behaves identically on every platform CI runs on.
//
// That is deliberate. This module is the one place the four previously
// duplicated spawn wrappers converged, and their shared defect (a signal-killed
// child reported as exit 0) survived precisely because no test ever executed
// any of them. Injecting a fake here would reproduce that blind spot.

const NODE = process.execPath;

// Run a snippet in a child node process. Kept as a helper so each test reads as
// one line of intent rather than an argv incantation.
function node(script: string, options = {}) {
  return spawnCapture(NODE, ['-e', script], options);
}

describe('spawnCapture — normal exits', () => {
  it('captures stdout and stderr into separate fields', async () => {
    const result = await node(
      'process.stdout.write("out"); process.stderr.write("err")',
    );
    expect(result.stdout).toBe('out');
    expect(result.stderr).toBe('err');
    expect(result.exitCode).toBe(0);
    expect(result.signal).toBeNull();
  });

  it('reports a non-zero exit code verbatim', async () => {
    const result = await node('process.exit(3)');
    expect(result.exitCode).toBe(3);
    expect(result.signal).toBeNull();
  });

  it('runs the child in the requested working directory', async () => {
    // realpath because macOS reports /tmp as a symlink to /private/tmp, which
    // process.cwd() in the child resolves.
    const dir = realpathSync(tmpdir());
    const result = await node('process.stdout.write(process.cwd())', { cwd: dir });
    expect(result.stdout).toBe(dir);
  });
});

describe('spawnCapture — signal termination (must never read as success)', () => {
  it('reports a non-zero exit code for a child killed by SIGKILL', async () => {
    // The case that justifies this whole test file. Under the old
    // `exitCode: code ?? 0` this resolved to exit 0, which the patcher then
    // recorded as 'patched-tests-passed' for an OOM-killed suite.
    const result = await node('process.kill(process.pid, "SIGKILL")');
    expect(result.exitCode).not.toBe(0);
  });

  it('surfaces the terminating signal name rather than discarding it', async () => {
    const result = await node('process.kill(process.pid, "SIGKILL")');
    expect(result.signal).toBe('SIGKILL');
  });

  it('maps SIGKILL to the conventional 128 + signal number (137)', async () => {
    const result = await node('process.kill(process.pid, "SIGKILL")');
    expect(result.exitCode).toBe(137);
  });

  it('maps SIGTERM to the conventional 128 + signal number (143)', async () => {
    const result = await node('process.kill(process.pid, "SIGTERM")');
    expect(result.exitCode).toBe(143);
    expect(result.signal).toBe('SIGTERM');
  });
});

describe('spawnCapture — missing binary', () => {
  const MISSING = 'corsec-definitely-not-a-real-binary';

  it('rejects with the supplied not-found message when the binary is absent', async () => {
    await expect(
      spawnCapture(MISSING, [], { notFoundMessage: `custom hint for ${MISSING}` }),
    ).rejects.toThrow(`custom hint for ${MISSING}`);
  });

  it('rejects with the underlying ENOENT error when no message is supplied', async () => {
    await expect(spawnCapture(MISSING, [])).rejects.toThrow(/ENOENT/);
  });
});

describe('spawnCapture — shell mode', () => {
  it('runs a command string verbatim through a shell', async () => {
    const result = await spawnCapture('echo shell-ran', [], { shell: true });
    expect(result.stdout.trim()).toBe('shell-ran');
    expect(result.exitCode).toBe(0);
  });

  it('reports the shell’s own 127 for an unknown command (no ENOENT to translate)', async () => {
    const result = await spawnCapture('corsec-definitely-not-a-real-binary', [], {
      shell: true,
    });
    expect(result.exitCode).toBe(127);
  });
});
