import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runHunter } from '../src/hunter/run.js';
import type { Advisory, Ecosystem, MatchedThreat } from '../src/hunter/types.js';

const fix = (name: string): string =>
  fileURLToPath(new URL(`../fixtures/lockfiles/${name}`, import.meta.url));

const rawFixture = JSON.parse(
  readFileSync(new URL('../fixtures/github-advisory-api.json', import.meta.url), 'utf-8'),
) as { data: { securityAdvisories: { nodes: Record<string, unknown>[] } } };

const fixtureAdvisories: Advisory[] = rawFixture.data.securityAdvisories.nodes.map(n => ({
  ...n,
  cvss: null,
})) as Advisory[];

// Creates a no-op fetcher that returns a fixed advisory list.
// Keeps GITHUB_TOKEN and network I/O out of tests without vi.mock() coupling.
function makeFetcher(advisories: Advisory[]) {
  return (_sinceISO: string, _ecosystem: Ecosystem): Promise<Advisory[]> =>
    Promise.resolve(advisories);
}

const baseOpts = {
  sinceISO: '2024-01-01T00:00:00Z',
  ecosystem: 'NPM' as Ecosystem,
};

// ---------------------------------------------------------------------------
// runHunter — vulnerable lockfile fixture (wrangler@3.10.0)
// Expected: 2 matches — GHSA-cfph-4qqh-w828 and GHSA-f8mp-x433-5wpf (>= 3.0.0 node)
// ---------------------------------------------------------------------------

describe('runHunter — vulnerable lockfile fixture', () => {
  it('returns { matchCount: 2 } and writes two MatchedThreats for wrangler@3.10.0', async () => {
    const outputPath = join(tmpdir(), `run-test-${randomUUID()}.json`);
    try {
      const result = await runHunter(
        {
          ...baseOpts,
          packageJsonPath: fix('vulnerable-package.json'),
          lockfilePath: fix('vulnerable-package-lock.json'),
          outputPath,
        },
        makeFetcher(fixtureAdvisories),
      );
      expect(result).toEqual({ matchCount: 2 });

      const written = JSON.parse(await readFile(outputPath, 'utf-8')) as MatchedThreat[];
      expect(written).toHaveLength(2);
      expect(written[0]).toMatchObject({
        ghsaId: 'GHSA-cfph-4qqh-w828',
        packageName: 'wrangler',
        installedVersion: '3.10.0',
      });
      expect(written[1]).toMatchObject({
        ghsaId: 'GHSA-f8mp-x433-5wpf',
        packageName: 'wrangler',
        installedVersion: '3.10.0',
      });
    } finally {
      await rm(outputPath, { force: true });
    }
  });

  it('writes valid JSON that round-trips through JSON.parse without throwing', async () => {
    const outputPath = join(tmpdir(), `run-test-${randomUUID()}.json`);
    try {
      await runHunter(
        {
          ...baseOpts,
          packageJsonPath: fix('vulnerable-package.json'),
          lockfilePath: fix('vulnerable-package-lock.json'),
          outputPath,
        },
        makeFetcher(fixtureAdvisories),
      );
      const raw = await readFile(outputPath, 'utf-8');
      expect(() => JSON.parse(raw)).not.toThrow();
      expect(Array.isArray(JSON.parse(raw))).toBe(true);
    } finally {
      await rm(outputPath, { force: true });
    }
  });

  it('output is sorted by ghsaId ascending (deterministic order from Slice 4)', async () => {
    const outputPath = join(tmpdir(), `run-test-${randomUUID()}.json`);
    try {
      await runHunter(
        {
          ...baseOpts,
          packageJsonPath: fix('vulnerable-package.json'),
          lockfilePath: fix('vulnerable-package-lock.json'),
          outputPath,
        },
        makeFetcher(fixtureAdvisories),
      );
      const matches = JSON.parse(await readFile(outputPath, 'utf-8')) as MatchedThreat[];
      const ids = matches.map(m => m.ghsaId);
      expect(ids).toEqual([...ids].sort());
    } finally {
      await rm(outputPath, { force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// runHunter — clean lockfile fixture (lodash@4.17.21, no advisory match)
// ---------------------------------------------------------------------------

describe('runHunter — clean lockfile fixture', () => {
  it('returns { matchCount: 0 } and writes [] when no advisories match installed deps', async () => {
    const outputPath = join(tmpdir(), `run-test-${randomUUID()}.json`);
    try {
      const result = await runHunter(
        {
          ...baseOpts,
          packageJsonPath: fix('clean-package.json'),
          lockfilePath: fix('clean-package-lock.json'),
          outputPath,
        },
        makeFetcher(fixtureAdvisories),
      );
      expect(result).toEqual({ matchCount: 0 });
      const written = JSON.parse(await readFile(outputPath, 'utf-8')) as unknown;
      expect(written).toEqual([]);
    } finally {
      await rm(outputPath, { force: true });
    }
  });
});
