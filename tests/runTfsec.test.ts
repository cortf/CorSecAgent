import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runTfsec, type TfsecExecutor } from '../src/cort/runTfsec.js';

// All fixtures live next to the suite in fixtures/tfsec/. Loading them at
// module level keeps the tests focused on assertions rather than file plumbing.
const cleanStdout = readFileSync(
  new URL('../fixtures/tfsec/clean-output.json', import.meta.url),
  'utf-8',
);
const findingsStdout = readFileSync(
  new URL('../fixtures/tfsec/findings-output.json', import.meta.url),
  'utf-8',
);
const malformedStdout = readFileSync(
  new URL('../fixtures/tfsec/malformed-output.json', import.meta.url),
  'utf-8',
);

// runTfsec pre-flights the directory via fs.stat, so the path passed to it
// has to actually exist. We use the fixtures directory itself — guaranteed to
// be a directory, and contains no .tf files, but that does not matter because
// the executor is mocked.
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(here, '../fixtures/tfsec');

function makeExecutor(stdout: string, stderr = '', exitCode = 0): TfsecExecutor {
  return vi.fn().mockResolvedValue({ stdout, stderr, exitCode });
}

describe('runTfsec — clean output (no failed checks)', () => {
  it('returns a TfsecReport with empty failed array and summary.failed === 0', async () => {
    const executor = makeExecutor(cleanStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    expect(report.failed).toEqual([]);
    expect(report.summary.failed).toBe(0);
    expect(report.passed.length).toBe(2);
  });

  it('summary counts match the array lengths exactly', async () => {
    const executor = makeExecutor(cleanStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    expect(report.summary.passed).toBe(report.passed.length);
    expect(report.summary.failed).toBe(report.failed.length);
  });

  it('produces empty arrays and zero summary counts when results[] is empty', async () => {
    const executor = makeExecutor(JSON.stringify({ results: [] }));
    const report = await runTfsec(FIXTURE_DIR, executor);

    expect(report.passed).toEqual([]);
    expect(report.failed).toEqual([]);
    expect(report.summary).toEqual({ passed: 0, failed: 0 });
  });
});

describe('runTfsec — findings output (mixed pass/fail)', () => {
  it('partitions results[] into passed and failed arrays based on the status field', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    expect(report.passed).toHaveLength(1);
    expect(report.failed).toHaveLength(3);
    expect(report.passed.every((f) => f.status === 'passed')).toBe(true);
    expect(report.failed.every((f) => f.status === 'failed')).toBe(true);
  });

  it('summary counts match the partitioned array lengths', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    expect(report.summary).toEqual({ passed: 1, failed: 3 });
  });

  it('preserves all three severities (HIGH, CRITICAL, MEDIUM) across failed findings', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    const severities = report.failed.map((f) => f.severity);
    expect(severities).toContain('HIGH');
    expect(severities).toContain('CRITICAL');
    expect(severities).toContain('MEDIUM');
  });

  it('projects raw tfsec fields (location.filename / start_line / end_line / resolution) into the normalised TfsecFinding shape', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    const imds = report.failed.find((f) => f.ruleId === 'AVD-AWS-0028');
    expect(imds).toBeDefined();
    expect(imds!.ruleDescription).toMatch(/IMDS/);
    expect(imds!.severity).toBe('HIGH');
    expect(imds!.filePath).toBe('/repo/terraform/ec2.tf');
    expect(imds!.lineRange).toEqual([10, 25]);
    expect(imds!.resource).toBe('aws_instance.app');
    expect(imds!.resolution).toBe('Enable HTTP token requirement for IMDS');
  });
});

describe('runTfsec — executor invocation', () => {
  it('passes the directory as a positional argument (NOT preceded by -d) and includes --format json --soft-fail', async () => {
    const executor = makeExecutor(cleanStdout);
    await runTfsec(FIXTURE_DIR, executor);

    expect(executor).toHaveBeenCalledTimes(1);
    expect(executor).toHaveBeenCalledWith([FIXTURE_DIR, '--format', 'json', '--soft-fail']);

    // Behavioural difference from Checkov worth its own assertion: the
    // directory is in position 0 and is NOT preceded by a -d flag.
    const args = (executor as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string[];
    expect(args[0]).toBe(FIXTURE_DIR);
    expect(args).not.toContain('-d');
  });
});

describe('runTfsec — invalid stdout (should throw)', () => {
  it('throws an error naming the directory when stdout is not valid JSON', async () => {
    const executor = makeExecutor(malformedStdout);
    await expect(runTfsec(FIXTURE_DIR, executor)).rejects.toThrow(/failed to parse/i);
    await expect(runTfsec(FIXTURE_DIR, executor)).rejects.toThrow(FIXTURE_DIR);
  });
});

describe('runTfsec — non-zero exit code (should throw)', () => {
  it('throws an error naming the exit code and stderr when tfsec fails', async () => {
    const executor = makeExecutor('', 'fatal: parse error in main.tf', 2);
    await expect(runTfsec(FIXTURE_DIR, executor)).rejects.toThrow(/exited with code 2/);
    await expect(runTfsec(FIXTURE_DIR, executor)).rejects.toThrow(/parse error in main\.tf/);
  });
});

describe('runTfsec — missing directory (should throw)', () => {
  it('throws an error naming the missing directory before invoking the executor', async () => {
    const executor = makeExecutor(cleanStdout);
    const missing = resolve(FIXTURE_DIR, 'does-not-exist-' + Date.now());

    await expect(runTfsec(missing, executor)).rejects.toThrow(/does not exist/);
    await expect(runTfsec(missing, executor)).rejects.toThrow(missing);
    expect(executor).not.toHaveBeenCalled();
  });
});

describe('tfsec fixture — findings-output.json (AVD-AWS-0088 critical S3 encryption)', () => {
  it('produces a CRITICAL-severity failed finding for the unencrypted S3 bucket', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runTfsec(FIXTURE_DIR, executor);

    const s3 = report.failed.find((f) => f.ruleId === 'AVD-AWS-0088');
    expect(s3).toBeDefined();
    expect(s3!.severity).toBe('CRITICAL');
    expect(s3!.resource).toBe('aws_s3_bucket.public');
    expect(s3!.filePath).toBe('/repo/terraform/s3.tf');
  });
});
