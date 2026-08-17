import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { loadInstalledVersions, matchAdvisoriesAgainstDeps } from '../src/hunter/matchDependencies.js';
import type { Advisory } from '../src/hunter/types.js';

// Helper: resolve a path inside fixtures/lockfiles/ relative to this file.
const fix = (name: string): string =>
  fileURLToPath(new URL(`../fixtures/lockfiles/${name}`, import.meta.url));

// Load and normalize the advisory fixture. The fixture was recorded without
// the cvss field in the query, so we add cvss: null — matching what the live
// API returns for advisories with no score assigned.
const rawFixture = JSON.parse(
  readFileSync(new URL('../fixtures/github-advisory-api.json', import.meta.url), 'utf-8'),
) as { data: { securityAdvisories: { nodes: Record<string, unknown>[] } } };

const fixtureAdvisories: Advisory[] = rawFixture.data.securityAdvisories.nodes.map(n => ({
  ...n,
  cvss: null,
})) as Advisory[];

// ---------------------------------------------------------------------------
// loadInstalledVersions — declared dependencies
// ---------------------------------------------------------------------------

describe('loadInstalledVersions — declared direct dependencies', () => {
  it('returns the installed version for a declared direct dep (lodash in clean fixture)', async () => {
    const installed = await loadInstalledVersions(
      fix('clean-package.json'),
      fix('clean-package-lock.json'),
    );
    expect(installed.get('lodash')).toBe('4.17.21');
  });

  it('excludes transitive deps that appear in the lockfile but are absent from package.json', async () => {
    const installed = await loadInstalledVersions(
      fix('clean-package.json'),
      fix('clean-package-lock.json'),
    );
    // some-transitive is in the lockfile but not declared in clean-package.json
    expect(installed.has('some-transitive')).toBe(false);
  });

  it('resolves wrangler@3.10.0 from the vulnerable fixture (devDependencies are included)', async () => {
    const installed = await loadInstalledVersions(
      fix('vulnerable-package.json'),
      fix('vulnerable-package-lock.json'),
    );
    expect(installed.get('wrangler')).toBe('3.10.0');
  });
});

// ---------------------------------------------------------------------------
// loadInstalledVersions — lockfile shapes the simple fixtures do not cover
// ---------------------------------------------------------------------------

describe('loadInstalledVersions — scoped, nested, and declared-but-absent entries', () => {
  const nested = () =>
    loadInstalledVersions(fix('nested-package.json'), fix('nested-package-lock.json'));

  it('resolves a scoped package from its hoisted root entry (@scope/pkg)', async () => {
    const installed = await nested();
    expect(installed.get('@scope/pkg')).toBe('2.1.4');
  });

  it('resolves a scoped devDependency the same way (@types/node)', async () => {
    const installed = await nested();
    expect(installed.get('@types/node')).toBe('22.13.1');
  });

  it('takes the hoisted root version, never a nested duplicate under another package', async () => {
    // The lockfile carries node_modules/vite/node_modules/@types/node at
    // 18.19.0 and node_modules/vite/node_modules/@scope/pkg at 1.0.0. Only the
    // hoisted entries are the installed versions for the direct deps.
    const installed = await nested();
    expect(installed.get('@types/node')).not.toBe('18.19.0');
    expect(installed.get('@scope/pkg')).not.toBe('1.0.0');
  });

  it('never manufactures an entry from a nested key path', async () => {
    // A name like "vite/node_modules/@types/node" is not a package name — npm
    // names cannot contain '/' outside a scope prefix. No such key may leak
    // into the result map.
    const installed = await nested();
    for (const name of installed.keys()) {
      expect(name).not.toContain('node_modules');
    }
    expect(installed.has('rollup/node_modules/@types/estree')).toBe(false);
  });

  it('omits a declared dependency that has no lockfile entry (never-installed)', async () => {
    const installed = await nested();
    expect(installed.has('never-installed')).toBe(false);
  });

  it('omits a lockfile entry that is not a declared direct dependency (rollup)', async () => {
    const installed = await nested();
    expect(installed.has('rollup')).toBe(false);
  });

  it('resolves exactly the declared deps that are present, and nothing else', async () => {
    const installed = await nested();
    expect([...installed.keys()].sort()).toEqual(['@scope/pkg', '@types/node', 'vite']);
  });
});

// ---------------------------------------------------------------------------
// loadInstalledVersions — error paths
// ---------------------------------------------------------------------------

describe('loadInstalledVersions — error paths (missing file)', () => {
  it('throws with the missing path in the error message when package.json does not exist', async () => {
    const missingPath = '/nonexistent/path/package.json';
    await expect(
      loadInstalledVersions(missingPath, fix('clean-package-lock.json')),
    ).rejects.toThrow(missingPath);
  });

  it('throws with the missing path in the error message when the lockfile does not exist', async () => {
    const missingPath = '/nonexistent/path/package-lock.json';
    await expect(
      loadInstalledVersions(fix('clean-package.json'), missingPath),
    ).rejects.toThrow(missingPath);
  });
});

describe('loadInstalledVersions — error paths (malformed JSON)', () => {
  it('throws with the file path in the error message when package.json contains malformed JSON', async () => {
    const malformedPath = fix('malformed.json');
    await expect(
      loadInstalledVersions(malformedPath, fix('clean-package-lock.json')),
    ).rejects.toThrow(malformedPath);
  });

  it('throws with the file path in the error message when the lockfile contains malformed JSON', async () => {
    const malformedPath = fix('malformed.json');
    await expect(
      loadInstalledVersions(fix('clean-package.json'), malformedPath),
    ).rejects.toThrow(malformedPath);
  });
});

// ---------------------------------------------------------------------------
// matchAdvisoriesAgainstDeps — no matches
// ---------------------------------------------------------------------------

describe('matchAdvisoriesAgainstDeps — no matches', () => {
  it('returns an empty array when the installed map is empty', () => {
    const result = matchAdvisoriesAgainstDeps(fixtureAdvisories, new Map());
    expect(result).toEqual([]);
  });

  it('returns an empty array when no installed package appears in any advisory', () => {
    const installed = new Map([['express', '4.18.0']]);
    const result = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);
    expect(result).toEqual([]);
  });

  it('returns an empty array when the installed version is outside all advisory ranges', () => {
    // wrangler@3.19.0 is the patch boundary — exclusive upper bound, not in range
    const installed = new Map([['wrangler', '3.19.0']]);
    const result = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);
    expect(result).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// matchAdvisoriesAgainstDeps — single match
// ---------------------------------------------------------------------------

describe('matchAdvisoriesAgainstDeps — single-node advisory match', () => {
  it('returns one MatchedThreat with all fields populated when a single-node advisory matches', () => {
    const advisory: Advisory = {
      ghsaId: 'GHSA-cfph-4qqh-w828',
      summary: 'Arbitrary remote file read in Wrangler dev server',
      severity: 'MODERATE',
      cvss: null,
      vulnerabilities: {
        nodes: [
          {
            package: { name: 'wrangler', ecosystem: 'NPM' },
            vulnerableVersionRange: '>= 3.9.0, < 3.19.0',
            firstPatchedVersion: { identifier: '3.19.0' },
          },
        ],
      },
    };
    const installed = new Map([['wrangler', '3.10.0']]);
    const result = matchAdvisoriesAgainstDeps([advisory], installed);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      ghsaId: 'GHSA-cfph-4qqh-w828',
      packageName: 'wrangler',
      installedVersion: '3.10.0',
      vulnerableRange: '>= 3.9.0, < 3.19.0',
      patchedVersion: '3.19.0',
      severity: 'MODERATE',
      cvssScore: null,
      summary: 'Arbitrary remote file read in Wrangler dev server',
    });
  });

  it('sets patchedVersion to null when firstPatchedVersion is null', () => {
    const advisory: Advisory = {
      ghsaId: 'GHSA-test-0000-0000',
      summary: 'Unpatched test advisory',
      severity: 'HIGH',
      cvss: { score: 7.5 },
      vulnerabilities: {
        nodes: [
          {
            package: { name: 'wrangler', ecosystem: 'NPM' },
            vulnerableVersionRange: '>= 3.9.0, < 3.19.0',
            firstPatchedVersion: null,
          },
        ],
      },
    };
    const installed = new Map([['wrangler', '3.10.0']]);
    const result = matchAdvisoriesAgainstDeps([advisory], installed);

    expect(result).toHaveLength(1);
    expect(result[0]?.patchedVersion).toBeNull();
    expect(result[0]?.cvssScore).toBe(7.5);
  });
});

// ---------------------------------------------------------------------------
// matchAdvisoriesAgainstDeps — deterministic ordering
// ---------------------------------------------------------------------------

describe('matchAdvisoriesAgainstDeps — deterministic ordering', () => {
  it('returns identical results on two consecutive calls with the same inputs', () => {
    const installed = new Map([['wrangler', '3.10.0']]);
    const first = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);
    const second = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);
    expect(first).toEqual(second);
  });
});

// ---------------------------------------------------------------------------
// GitHub Advisory fixture — wrangler@3.10.0 (overlapping ranges)
// wrangler@3.10.0 falls inside:
//   GHSA-cfph-4qqh-w828 node:  >= 3.9.0, < 3.19.0   ✓
//   GHSA-f8mp-x433-5wpf node2: >= 3.0.0, < 3.19.0   ✓
//   GHSA-f8mp-x433-5wpf node1: >= 2.0.0, < 2.20.2   ✗
// Expected: 2 matches, sorted by ghsaId asc.
// ---------------------------------------------------------------------------

describe('GitHub Advisory fixture — wrangler@3.10.0 overlapping ranges', () => {
  it('produces 2 MatchedThreats from GHSA-cfph-4qqh-w828 and the >= 3.0.0 node of GHSA-f8mp-x433-5wpf', () => {
    const installed = new Map([['wrangler', '3.10.0']]);
    const result = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);

    expect(result).toHaveLength(2);

    // Sorted by ghsaId: GHSA-cfph-4qqh-w828 < GHSA-f8mp-x433-5wpf
    expect(result[0]).toMatchObject({
      ghsaId: 'GHSA-cfph-4qqh-w828',
      packageName: 'wrangler',
      installedVersion: '3.10.0',
      vulnerableRange: '>= 3.9.0, < 3.19.0',
      patchedVersion: '3.19.0',
      severity: 'MODERATE',
      cvssScore: null,
    });
    expect(result[1]).toMatchObject({
      ghsaId: 'GHSA-f8mp-x433-5wpf',
      packageName: 'wrangler',
      installedVersion: '3.10.0',
      vulnerableRange: '>= 3.0.0, < 3.19.0',
      patchedVersion: '3.19.0',
      severity: 'CRITICAL',
      cvssScore: null,
    });
  });
});

// ---------------------------------------------------------------------------
// GitHub Advisory fixture — GHSA-f8mp-x433-5wpf multi-node (wrangler@2.10.0)
// wrangler@2.10.0 falls inside:
//   GHSA-cfph-4qqh-w828 node:  >= 3.9.0, < 3.19.0   ✗
//   GHSA-f8mp-x433-5wpf node1: >= 2.0.0, < 2.20.2   ✓
//   GHSA-f8mp-x433-5wpf node2: >= 3.0.0, < 3.19.0   ✗
// Expected: exactly 1 match, not 2.
// ---------------------------------------------------------------------------

describe('GitHub Advisory fixture — GHSA-f8mp-x433-5wpf multi-node (wrangler@2.10.0)', () => {
  it('produces exactly 1 match when only the >= 2.0.0, < 2.20.2 node covers the installed version', () => {
    const installed = new Map([['wrangler', '2.10.0']]);
    const result = matchAdvisoriesAgainstDeps(fixtureAdvisories, installed);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      ghsaId: 'GHSA-f8mp-x433-5wpf',
      packageName: 'wrangler',
      installedVersion: '2.10.0',
      vulnerableRange: '>= 2.0.0, < 2.20.2',
      patchedVersion: '2.20.2',
      severity: 'CRITICAL',
    });
  });
});
