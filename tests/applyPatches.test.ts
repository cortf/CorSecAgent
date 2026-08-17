import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile, cp } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { applyPatches } from '../src/patcher/applyPatches.js';
import type {
  GitExecutor,
  NpmExecutor,
  ShellExecutor,
} from '../src/patcher/applyPatches.js';
import type { PatchSession } from '../src/patcher/types.js';

// -----------------------------------------------------------------------------
// Fixtures and helpers
// -----------------------------------------------------------------------------

const FIXTURE_PKG_JSON = fileURLToPath(
  new URL('../fixtures/patcher/package.json', import.meta.url),
);
const FIXTURE_LOCK_BEFORE = fileURLToPath(
  new URL('../fixtures/patcher/lockfile-before.json', import.meta.url),
);

// Loaded at module level (the canonical pattern from CLAUDE.md). Used for
// shape assertions and to seed the matches.json input file in each test.
const matchesSingleRaw = readFileSync(
  new URL('../fixtures/patcher/matches-single.json', import.meta.url),
  'utf-8',
);
const matchesMultiSameRaw = readFileSync(
  new URL('../fixtures/patcher/matches-multi-same-package.json', import.meta.url),
  'utf-8',
);
const matchesNoFixRaw = readFileSync(
  new URL('../fixtures/patcher/matches-no-fix.json', import.meta.url),
  'utf-8',
);
const matchesAlreadyResolvedRaw = readFileSync(
  new URL('../fixtures/patcher/matches-already-resolved.json', import.meta.url),
  'utf-8',
);
const matchesMultiDifferentRaw = readFileSync(
  new URL('../fixtures/patcher/matches-multi-different-packages.json', import.meta.url),
  'utf-8',
);
const matchesNonSemverPatchRaw = readFileSync(
  new URL('../fixtures/patcher/matches-non-semver-patch.json', import.meta.url),
  'utf-8',
);

// Set up a fresh temp working directory with the canonical package.json +
// lockfile-before in place, and a matches.json file containing the supplied
// raw payload. Returns the paths the test will pass to applyPatches.
async function setupWorkdir(matchesRaw: string): Promise<{
  workingDir: string;
  matchesPath: string;
  outputPath: string;
  cleanup: () => Promise<void>;
}> {
  const workingDir = join(tmpdir(), `patcher-test-${randomUUID()}`);
  await mkdir(workingDir, { recursive: true });
  await cp(FIXTURE_PKG_JSON, join(workingDir, 'package.json'));
  await cp(FIXTURE_LOCK_BEFORE, join(workingDir, 'package-lock.json'));
  const matchesPath = join(workingDir, 'matches.json');
  const outputPath = join(workingDir, 'patch-session.json');
  await writeFile(matchesPath, matchesRaw, 'utf-8');
  return {
    workingDir,
    matchesPath,
    outputPath,
    cleanup: () => rm(workingDir, { recursive: true, force: true }),
  };
}

// A git executor that succeeds quietly. We use the spy on .mock.calls to
// verify the branch creation invariant ("created exactly once").
function makeGit(exitCode = 0, stderr = ''): GitExecutor {
  return vi.fn().mockResolvedValue({ stdout: '', stderr, exitCode });
}

// An npm executor that, on each call, mutates the lockfile in the workingDir
// to simulate npm install bumping a single package. `installs` maps package
// name -> behaviour. A version string means "bump to this version on
// install". The literal value 'fail' means "exit non-zero, don't touch the
// lockfile".
function makeNpm(installs: Record<string, string | 'fail'>): NpmExecutor {
  return vi.fn().mockImplementation(async (args: string[], cwd: string) => {
    // args looks like ['install', 'wrangler@^3.25.0']
    const pkgArg = args[1] ?? '';
    // ^ trailing @<spec> follows the last '@' — splitting on '@^' is brittle
    // because scoped packages contain '@', so search for '@^' directly.
    const atCaretIdx = pkgArg.indexOf('@^');
    const name = atCaretIdx >= 0 ? pkgArg.slice(0, atCaretIdx) : pkgArg;
    const sim = installs[name];
    if (sim === undefined || sim === 'fail') {
      return {
        stdout: '',
        stderr: `npm ERR! could not install ${name}`,
        exitCode: 1,
      };
    }
    const lockPath = join(cwd, 'package-lock.json');
    const lock = JSON.parse(await readFile(lockPath, 'utf-8')) as {
      packages?: Record<string, { version?: string }>;
    };
    if (!lock.packages) lock.packages = {};
    lock.packages[`node_modules/${name}`] = { version: sim };
    await writeFile(lockPath, JSON.stringify(lock, null, 2), 'utf-8');
    return { stdout: `added ${name}@${sim}`, stderr: '', exitCode: 0 };
  });
}

function makeShell(exitCode: number, stdout = '', stderr = ''): ShellExecutor {
  return vi.fn().mockResolvedValue({ stdout, stderr, exitCode });
}

// -----------------------------------------------------------------------------
// applyPatches — empty matches input
// -----------------------------------------------------------------------------

describe('applyPatches — empty matches input', () => {
  it('produces a PatchSession with no results and zero counts (and never invokes git/npm/shell)', async () => {
    const ctx = await setupWorkdir('[]');
    try {
      const git = makeGit();
      const npm = makeNpm({});
      const shell = makeShell(0);

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(session.results).toEqual([]);
      expect(session.testRun).toBeNull();
      expect(session.summary).toEqual({
        total: 0,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      });
      expect(git).not.toHaveBeenCalled();
      expect(npm).not.toHaveBeenCalled();
      expect(shell).not.toHaveBeenCalled();
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — single match, install succeeds, tests pass
// -----------------------------------------------------------------------------

describe('applyPatches — single match, install succeeds, tests pass', () => {
  it('runs one npm install, one shell (test), one git checkout, and produces patched-tests-passed', async () => {
    const ctx = await setupWorkdir(matchesSingleRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({ lodash: '4.17.22' });
      const shell = makeShell(0, 'All 42 tests passed', '');

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(git).toHaveBeenCalledTimes(1);
      expect(git).toHaveBeenCalledWith(
        ['checkout', '-b', expect.stringMatching(/^corsec\/hotfix\/\d+$/) as unknown as string],
        ctx.workingDir,
      );
      expect(npm).toHaveBeenCalledTimes(1);
      expect(npm).toHaveBeenCalledWith(['install', 'lodash@^4.17.21'], ctx.workingDir);
      expect(shell).toHaveBeenCalledTimes(1);
      expect(shell).toHaveBeenCalledWith('npm test', ctx.workingDir);

      expect(session.results).toHaveLength(1);
      expect(session.results[0]).toMatchObject({
        packageName: 'lodash',
        previousVersion: '4.17.20',
        targetVersion: '4.17.21',
        installedVersion: '4.17.22',
        status: 'patched-tests-passed',
        relatedMatches: ['GHSA-jf85-cpcp-j695'],
        errorMessage: null,
      });
      expect(session.testRun?.status).toBe('passed');
      expect(session.testRun?.output).toContain('All 42 tests passed');
      expect(session.summary).toEqual({
        total: 1,
        byStatus: {
          'patched-tests-passed': 1,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      });
      expect(session.branchName).toMatch(/^corsec\/hotfix\/\d+$/);
    } finally {
      await ctx.cleanup();
    }
  });

  it('writes the PatchSession to outputPath as 2-space-indented JSON that round-trips', async () => {
    const ctx = await setupWorkdir(matchesSingleRaw);
    try {
      await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git: makeGit(), npm: makeNpm({ lodash: '4.17.22' }), shell: makeShell(0) },
      );
      const raw = await readFile(ctx.outputPath, 'utf-8');
      const parsed = JSON.parse(raw) as PatchSession;
      expect(parsed.results).toHaveLength(1);
      expect(raw).toContain('\n  '); // 2-space indent marker
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — multi-match same package consolidates into one install
// -----------------------------------------------------------------------------

describe('applyPatches — multi-match same package (consolidation)', () => {
  it('runs ONE npm install with the higher patched version, listing BOTH GHSAs in relatedMatches', async () => {
    const ctx = await setupWorkdir(matchesMultiSameRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({ wrangler: '3.27.0' });
      const shell = makeShell(0);

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(npm).toHaveBeenCalledTimes(1);
      expect(npm).toHaveBeenCalledWith(['install', 'wrangler@^3.25.0'], ctx.workingDir);
      expect(session.results).toHaveLength(1);
      expect(session.results[0]!.packageName).toBe('wrangler');
      expect(session.results[0]!.targetVersion).toBe('3.25.0');
      expect(session.results[0]!.installedVersion).toBe('3.27.0');
      expect(session.results[0]!.status).toBe('patched-tests-passed');
      // Sorted alphabetically.
      expect(session.results[0]!.relatedMatches).toEqual([
        'GHSA-cfph-4qqh-w828',
        'GHSA-f8mp-x433-5wpf',
      ]);
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — no fix available
// -----------------------------------------------------------------------------

describe('applyPatches — no fix available (patchedVersion: null)', () => {
  it('produces patch-failed-no-fix-available without calling npm, git, or shell', async () => {
    const ctx = await setupWorkdir(matchesNoFixRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({});
      const shell = makeShell(0);

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(npm).not.toHaveBeenCalled();
      expect(git).not.toHaveBeenCalled();
      expect(shell).not.toHaveBeenCalled();
      expect(session.results).toHaveLength(1);
      expect(session.results[0]).toMatchObject({
        packageName: 'unpatched-pkg',
        targetVersion: null,
        installedVersion: null,
        status: 'patch-failed-no-fix-available',
        errorMessage: null,
      });
      // No install succeeded, so the suite never ran.
      expect(session.testRun).toBeNull();
      expect(session.summary).toEqual({
        total: 1,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 1,
          'skipped-already-resolved': 0,
        },
      });
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — already-resolved skips install entirely
// -----------------------------------------------------------------------------

describe('applyPatches — already-resolved by current lockfile', () => {
  it('produces skipped-already-resolved without calling npm, git, or shell when the lockfile is already >= patchedVersion', async () => {
    // matches-already-resolved.json targets resolved-pkg with patchedVersion
    // 4.5.0, while lockfile-before.json has resolved-pkg at 5.1.0 — so the
    // lockfile already satisfies the patch, even though Hunter saw the older
    // 4.0.0.
    const ctx = await setupWorkdir(matchesAlreadyResolvedRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({});
      const shell = makeShell(0);

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(npm).not.toHaveBeenCalled();
      expect(git).not.toHaveBeenCalled();
      expect(shell).not.toHaveBeenCalled();
      expect(session.results).toHaveLength(1);
      expect(session.results[0]).toMatchObject({
        packageName: 'resolved-pkg',
        previousVersion: '5.1.0',
        targetVersion: '4.5.0',
        installedVersion: '5.1.0',
        status: 'skipped-already-resolved',
      });

      // This is the status the old four-counter summary had no bucket for: it
      // was counted in `attempted` and in nothing else, so the session read as
      // "one attempt, none succeeded, no reason recorded" for a run in which
      // npm, git and the test command were never invoked.
      expect(session.summary).toEqual({
        total: 1,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 1,
        },
      });
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — install failure on one package does not abort the session
// -----------------------------------------------------------------------------

describe('applyPatches — install failure on one package does not abort the session', () => {
  it('still attempts the other package and produces both results', async () => {
    const ctx = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const git = makeGit();
      // pkg-a fails on install, pkg-b succeeds.
      const npm = makeNpm({ 'pkg-a': 'fail', 'pkg-b': '3.5.0' });
      const shell = makeShell(0, 'all good');

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(npm).toHaveBeenCalledTimes(2);
      // Tests still run for the successfully-installed package (pkg-b).
      expect(shell).toHaveBeenCalledTimes(1);

      expect(session.results).toHaveLength(2);
      const a = session.results.find((r) => r.packageName === 'pkg-a');
      const b = session.results.find((r) => r.packageName === 'pkg-b');
      expect(a).toMatchObject({
        status: 'patch-failed-install-error',
        installedVersion: null,
        targetVersion: '2.0.0',
      });
      expect(a!.errorMessage).toMatch(/could not install pkg-a/);
      expect(b).toMatchObject({
        status: 'patched-tests-passed',
        installedVersion: '3.5.0',
        targetVersion: '3.0.0',
      });

      expect(session.summary).toEqual({
        total: 2,
        byStatus: {
          'patched-tests-passed': 1,
          'patched-tests-failed': 0,
          'patch-failed-install-error': 1,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      });
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — test failure marks ALL successfully-installed packages as
// patched-tests-failed (shared test run semantics)
// -----------------------------------------------------------------------------

describe('applyPatches — test failure (shared test run)', () => {
  it('marks every successfully-installed package as patched-tests-failed when the shared test run exits non-zero', async () => {
    const ctx = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const npm = makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': '3.5.0' });
      // Tests fail.
      const shell = makeShell(1, '', 'TypeError: cannot read property X of undefined\n    at line 42\n');

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git: makeGit(), npm, shell },
      );

      expect(shell).toHaveBeenCalledTimes(1);
      expect(session.results).toHaveLength(2);
      for (const r of session.results) {
        expect(r.status).toBe('patched-tests-failed');
      }
      // One shared run, recorded once — not copied onto each row.
      expect(session.testRun?.status).toBe('failed');
      expect(session.testRun?.output).toContain('TypeError');
      expect(session.summary).toEqual({
        total: 2,
        byStatus: {
          'patched-tests-passed': 0,
          'patched-tests-failed': 2,
          'patch-failed-install-error': 0,
          'patch-failed-no-fix-available': 0,
          'skipped-already-resolved': 0,
        },
      });
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — branch is created exactly once at the start
// -----------------------------------------------------------------------------

describe('applyPatches — branch creation invariant', () => {
  it('creates the branch exactly once (not per package) when multiple packages are installed', async () => {
    const ctx = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': '3.5.0' });
      const shell = makeShell(0);

      await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      expect(git).toHaveBeenCalledTimes(1);
      const callArgs = (git as unknown as { mock: { calls: [string[], string][] } }).mock.calls[0];
      expect(callArgs![0]).toEqual([
        'checkout',
        '-b',
        expect.stringMatching(/^corsec\/hotfix\/\d+$/) as unknown as string,
      ]);
    } finally {
      await ctx.cleanup();
    }
  });

  it('uses the supplied branchPrefix when provided', async () => {
    const ctx = await setupWorkdir(matchesSingleRaw);
    try {
      const git = makeGit();
      await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
          branchPrefix: 'patcher/test',
        },
        { git, npm: makeNpm({ lodash: '4.17.22' }), shell: makeShell(0) },
      );
      const call = (git as unknown as { mock: { calls: [string[], string][] } }).mock.calls[0];
      expect(call![0][2]).toMatch(/^patcher\/test\/\d+$/);
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — test output truncation
// -----------------------------------------------------------------------------

describe('applyPatches — test output truncation', () => {
  it('truncates the captured test output to 5 KiB, keeping the tail', async () => {
    const ctx = await setupWorkdir(matchesSingleRaw);
    try {
      // Distinct head sentinel (early in the stream) + ~10 KiB of filler +
      // a distinct tail sentinel. After truncation the head sentinel must
      // NOT survive (it sits before the kept-tail window) but the tail
      // sentinel must.
      const headSentinel = 'HEAD-SENTINEL-SHOULD-BE-DROPPED\n';
      const filler = 'A'.repeat(10 * 1024);
      const tailSentinel = '\nFAILED: trailing-sentinel-line\n';
      const shell = makeShell(0, headSentinel + filler + tailSentinel, '');

      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git: makeGit(), npm: makeNpm({ lodash: '4.17.22' }), shell },
      );

      const out = session.testRun!.output;
      const byteLength = Buffer.byteLength(out, 'utf-8');
      expect(byteLength).toBeLessThanOrEqual(5 * 1024);
      expect(byteLength).toBeGreaterThan(5 * 1024 - 200);
      expect(out).toContain('trailing-sentinel-line');
      expect(out).not.toContain('HEAD-SENTINEL-SHOULD-BE-DROPPED');
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — deterministic results ordering
// -----------------------------------------------------------------------------

describe('applyPatches — deterministic output', () => {
  it('produces results sorted alphabetically by packageName, and the same ordering across two runs', async () => {
    const ctx1 = await setupWorkdir(matchesMultiDifferentRaw);
    const ctx2 = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const sessionA = await applyPatches(
        {
          matchesPath: ctx1.matchesPath,
          outputPath: ctx1.outputPath,
          workingDir: ctx1.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          npm: makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': '3.5.0' }),
          shell: makeShell(0),
        },
      );
      const sessionB = await applyPatches(
        {
          matchesPath: ctx2.matchesPath,
          outputPath: ctx2.outputPath,
          workingDir: ctx2.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          npm: makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': '3.5.0' }),
          shell: makeShell(0),
        },
      );

      const namesA = sessionA.results.map((r) => r.packageName);
      const namesB = sessionB.results.map((r) => r.packageName);
      expect(namesA).toEqual(['pkg-a', 'pkg-b']);
      expect(namesA).toEqual(namesB);
    } finally {
      await ctx1.cleanup();
      await ctx2.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — a non-semver firstPatchedVersion must not sink the session
// -----------------------------------------------------------------------------

describe('applyPatches — advisory carries a non-semver firstPatchedVersion', () => {
  // The blast radius before isAtLeast: consolidateByPackage built a range by
  // concatenation ('>= 3.25.0.RELEASE'), isVersionInRange threw on the invalid
  // range, the throw escaped applyPatches entirely, and the orchestrator
  // replaced the whole stage with a synthetic empty session — so every other
  // package lost its patch over one bad identifier from the advisory feed.
  it('does not throw, and still patches the unrelated package in the same session', async () => {
    const ctx = await setupWorkdir(matchesNonSemverPatchRaw);
    try {
      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          npm: makeNpm({ wrangler: '3.25.0', 'pkg-b': '3.5.0' }),
          shell: makeShell(0),
        },
      );

      const pkgB = session.results.find((r) => r.packageName === 'pkg-b');
      expect(pkgB?.status).toBe('patched-tests-passed');
      expect(session.results).toHaveLength(2);
    } finally {
      await ctx.cleanup();
    }
  });

  it('keeps the comparable candidate rather than letting the unparseable one win', async () => {
    const ctx = await setupWorkdir(matchesNonSemverPatchRaw);
    try {
      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          npm: makeNpm({ wrangler: '3.25.0', 'pkg-b': '3.5.0' }),
          shell: makeShell(0),
        },
      );

      const wrangler = session.results.find((r) => r.packageName === 'wrangler');
      expect(wrangler?.targetVersion).toBe('3.20.0');
      expect(wrangler?.relatedMatches).toEqual([
        'GHSA-cfph-4qqh-w828',
        'GHSA-f8mp-x433-5wpf',
      ]);
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — session-level invariants
// -----------------------------------------------------------------------------

describe('applyPatches — a tests-* status and a recorded test run imply each other', () => {
  // The invariant the old placeholder shape could violate: between building the
  // row and the test run finishing, a PatchResult claimed
  // 'patched-tests-passed' for a suite that had not been spawned. Now that the
  // run is recorded once on the session, the statement is that a tests-* status
  // exists if and only if testRun does — and that its outcome agrees.
  it('holds in both directions across a session mixing tests-* and non-tests-* rows', async () => {
    const ctx = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          // pkg-a installs cleanly, pkg-b fails to install — so the session
          // carries one tests-* row and one non-tests-* row.
          npm: makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': 'fail' }),
          shell: makeShell(0, 'suite output'),
        },
      );

      const tested = session.results.filter((r) => r.status.startsWith('patched-tests-'));
      expect(tested.length > 0).toBe(session.testRun !== null);

      // Guard against the assertion above passing vacuously, and check that the
      // rows and the single recorded run agree on the outcome.
      expect(tested).toHaveLength(1);
      expect(session.results.some((r) => !r.status.startsWith('patched-tests-'))).toBe(true);
      expect(session.testRun?.status).toBe('passed');
      expect(tested.every((r) => r.status === 'patched-tests-passed')).toBe(true);
    } finally {
      await ctx.cleanup();
    }
  });

  it('keeps the summary total equal to the result count and to the sum of its buckets', async () => {
    // The gap that let the old four-counter summary go wrong: the
    // already-resolved test asserted results[0] but never asserted the summary,
    // so `attempted` counting a status with no bucket went unnoticed.
    const ctx = await setupWorkdir(matchesMultiDifferentRaw);
    try {
      const session = await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        {
          git: makeGit(),
          npm: makeNpm({ 'pkg-a': '2.5.0', 'pkg-b': 'fail' }),
          shell: makeShell(0),
        },
      );

      const bucketSum = Object.values(session.summary.byStatus).reduce((a, b) => a + b, 0);
      expect(session.summary.total).toBe(session.results.length);
      expect(bucketSum).toBe(session.summary.total);
    } finally {
      await ctx.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// applyPatches — default executors are not invoked when executors are injected
// (sanity check — proves no real spawn calls happen in the test suite)
// -----------------------------------------------------------------------------

describe('applyPatches — injected executors prevent any real spawn calls', () => {
  it('drives the whole pipeline through injected mocks, with each one called only as expected', async () => {
    const ctx = await setupWorkdir(matchesSingleRaw);
    try {
      const git = makeGit();
      const npm = makeNpm({ lodash: '4.17.22' });
      const shell = makeShell(0);

      await applyPatches(
        {
          matchesPath: ctx.matchesPath,
          outputPath: ctx.outputPath,
          workingDir: ctx.workingDir,
          testCommand: 'npm test',
        },
        { git, npm, shell },
      );

      // Each mock was called the expected number of times; if a real spawn had
      // happened, the mock counts would still match expectations *but* the
      // suite would have produced a real git branch (or attempted to). The
      // working dir is a fresh tmp folder with no .git/, so a real spawn
      // would have errored — passing through cleanly is the proof.
      expect(git).toHaveBeenCalledTimes(1);
      expect(npm).toHaveBeenCalledTimes(1);
      expect(shell).toHaveBeenCalledTimes(1);
    } finally {
      await ctx.cleanup();
    }
  });
});
