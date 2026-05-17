import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runCheckov, type CheckovExecutor } from '../src/cort/runCheckov.js';

// All fixtures live next to the suite in fixtures/checkov/. Loading them at
// module level keeps the tests focused on assertions rather than file plumbing.
const cleanStdout = readFileSync(
  new URL('../fixtures/checkov/clean-output.json', import.meta.url),
  'utf-8',
);
const findingsStdout = readFileSync(
  new URL('../fixtures/checkov/findings-output.json', import.meta.url),
  'utf-8',
);
const malformedStdout = readFileSync(
  new URL('../fixtures/checkov/malformed-output.json', import.meta.url),
  'utf-8',
);

// runCheckov pre-flights the directory via fs.stat, so the path passed to it
// has to actually exist. We use the fixtures directory itself — it is
// guaranteed to be a directory and contains no .tf files, but that does not
// matter because the executor is mocked.
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(here, '../fixtures/checkov');

function makeExecutor(stdout: string, stderr = '', exitCode = 0): CheckovExecutor {
  return vi.fn().mockResolvedValue({ stdout, stderr, exitCode });
}

describe('runCheckov — clean output (no failed checks)', () => {
  it('returns a CheckovReport with empty failed array and summary.failed === 0', async () => {
    const executor = makeExecutor(cleanStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    expect(report.failed).toEqual([]);
    expect(report.summary.failed).toBe(0);
    expect(report.passed.length).toBe(2);
    expect(report.skipped.length).toBe(0);
  });

  it('summary counts match the array lengths exactly', async () => {
    const executor = makeExecutor(cleanStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    expect(report.summary.passed).toBe(report.passed.length);
    expect(report.summary.failed).toBe(report.failed.length);
    expect(report.summary.skipped).toBe(report.skipped.length);
  });
});

describe('runCheckov — findings output (mixed pass/fail/skip)', () => {
  it('partitions checks into passed, failed, and skipped arrays by result', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    expect(report.passed).toHaveLength(1);
    expect(report.failed).toHaveLength(3);
    expect(report.skipped).toHaveLength(1);
    expect(report.passed.every(f => f.result === 'PASSED')).toBe(true);
    expect(report.failed.every(f => f.result === 'FAILED')).toBe(true);
    expect(report.skipped.every(f => f.result === 'SKIPPED')).toBe(true);
  });

  it('summary counts match the partitioned array lengths', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    expect(report.summary).toEqual({ passed: 1, failed: 3, skipped: 1 });
  });

  it('preserves all three severities (HIGH, CRITICAL, MEDIUM) across failed findings', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    const severities = report.failed.map(f => f.severity);
    expect(severities).toContain('HIGH');
    expect(severities).toContain('CRITICAL');
    expect(severities).toContain('MEDIUM');
  });

  it('projects raw Checkov fields into the normalised CheckovFinding shape', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    const imds = report.failed.find(f => f.checkId === 'CKV_AWS_79');
    expect(imds).toBeDefined();
    expect(imds!.checkName).toMatch(/IMDSv2/);
    expect(imds!.severity).toBe('HIGH');
    expect(imds!.filePath).toBe('/ec2.tf');
    expect(imds!.fileLineRange).toEqual([10, 25]);
    expect(imds!.resource).toBe('aws_instance.app');
    expect(imds!.guideline).toBe('https://docs.bridgecrew.io/docs/general_26');
  });

  it('preserves a null severity on the skipped check (Checkov omits severity on suppressions)', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    expect(report.skipped[0]?.severity).toBeNull();
  });
});

describe('runCheckov — executor invocation', () => {
  it('passes exactly [-d <dir> --framework terraform --output json --soft-fail] to the executor', async () => {
    const executor = makeExecutor(cleanStdout);
    await runCheckov(FIXTURE_DIR, executor);

    expect(executor).toHaveBeenCalledTimes(1);
    expect(executor).toHaveBeenCalledWith([
      '-d',
      FIXTURE_DIR,
      '--framework',
      'terraform',
      '--output',
      'json',
      '--soft-fail',
    ]);
  });
});

describe('runCheckov — invalid stdout (should throw)', () => {
  it('throws an error naming the directory when stdout is not valid JSON', async () => {
    const executor = makeExecutor(malformedStdout);
    await expect(runCheckov(FIXTURE_DIR, executor)).rejects.toThrow(/failed to parse/i);
    await expect(runCheckov(FIXTURE_DIR, executor)).rejects.toThrow(FIXTURE_DIR);
  });
});

describe('runCheckov — non-zero exit code (should throw)', () => {
  it('throws an error naming the exit code and stderr when checkov fails', async () => {
    const executor = makeExecutor('', 'fatal: configuration error', 2);
    await expect(runCheckov(FIXTURE_DIR, executor)).rejects.toThrow(/exited with code 2/);
    await expect(runCheckov(FIXTURE_DIR, executor)).rejects.toThrow(/configuration error/);
  });
});

describe('runCheckov — missing directory (should throw)', () => {
  it('throws an error naming the missing directory before invoking the executor', async () => {
    const executor = makeExecutor(cleanStdout);
    const missing = resolve(FIXTURE_DIR, 'does-not-exist-' + Date.now());

    await expect(runCheckov(missing, executor)).rejects.toThrow(/does not exist/);
    await expect(runCheckov(missing, executor)).rejects.toThrow(missing);
    expect(executor).not.toHaveBeenCalled();
  });
});

describe('Checkov fixture — findings-output.json (CKV_AWS_19 critical S3 encryption)', () => {
  it('produces a CRITICAL-severity failed finding for the unencrypted S3 bucket', async () => {
    const executor = makeExecutor(findingsStdout);
    const report = await runCheckov(FIXTURE_DIR, executor);

    const s3 = report.failed.find(f => f.checkId === 'CKV_AWS_19');
    expect(s3).toBeDefined();
    expect(s3!.severity).toBe('CRITICAL');
    expect(s3!.resource).toBe('aws_s3_bucket.public');
    expect(s3!.filePath).toBe('/s3.tf');
  });
});
