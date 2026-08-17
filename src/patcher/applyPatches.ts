import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { MatchedThreat } from '../hunter/types.js';
import { loadInstalledVersions } from '../hunter/matchDependencies.js';
import { isVersionInRange } from '../shared/semverRange.js';
import { spawnCapture } from '../shared/spawnCapture.js';
import type { PatchResult, PatchSession, PatchStatus } from './types.js';

// Captured stream + exit triple. Same shape that the Cort scanner executors
// return, so the testing pattern carries over.
type ExecResult = { stdout: string; stderr: string; exitCode: number };

// Three injectable executor shapes. The git/npm executors take an argv-style
// array (no shell interpretation); the shell executor takes the test command
// as a single string because the user provides it verbatim (e.g., "npm test"
// or "npm run test:integration -- --bail") and we should not parse it.
export type GitExecutor = (args: string[], cwd: string) => Promise<ExecResult>;
export type NpmExecutor = (args: string[], cwd: string) => Promise<ExecResult>;
export type ShellExecutor = (command: string, cwd: string) => Promise<ExecResult>;

export interface PatchExecutors {
  git?: GitExecutor;
  npm?: NpmExecutor;
  shell?: ShellExecutor;
}

export interface ApplyPatchesOptions {
  matchesPath: string;
  outputPath: string;
  workingDir: string;
  testCommand: string;
  branchPrefix?: string;
}

// 5 KiB. Test output is truncated tail-first so the failure context (which
// almost always surfaces near the end) survives.
const TEST_OUTPUT_MAX_BYTES = 5 * 1024;

// One row per package after collapsing matches that share a packageName.
interface ConsolidatedPatch {
  packageName: string;
  // Installed version reported by Hunter at scan time. Used as a fallback when
  // the current lockfile cannot be read; applyPatches normally re-reads.
  installedVersion: string;
  // The highest firstPatchedVersion seen across all matches for this package.
  // null when ANY match in the group has patchedVersion: null (no fix yet) —
  // we cannot safely patch some-but-not-all CVEs in the same package.
  targetVersion: string | null;
  // All GHSA IDs in this consolidation, sorted for deterministic output.
  ghsaIds: string[];
}

/**
 * Consume Hunter's matches.json and attempt deterministic remediation:
 *
 *   1. consolidate matches by package (one install per package, even if two
 *      GHSAs flagged it)
 *   2. for each package: skip if no-fix or already-resolved, otherwise run
 *      `npm install <pkg>@^<targetVersion>`
 *   3. after all installs, run the test command ONCE — all successfully
 *      installed packages share the test outcome
 *
 * Tests run once after all installs are complete. This trades isolation
 * (which package broke things) for simplicity and speed. If interaction bugs
 * prove common in practice, consider per-install test runs gated by a
 * `--isolated` flag.
 *
 * This function does NOT push the branch and does NOT open a PR. It creates
 * the branch locally and produces a PatchSession JSON file; orchestrating
 * the rest is a later slice.
 */
export async function applyPatches(
  opts: ApplyPatchesOptions,
  executors: PatchExecutors = {},
): Promise<PatchSession> {
  const git = executors.git ?? defaultGit;
  const npm = executors.npm ?? defaultNpm;
  const shell = executors.shell ?? defaultShell;

  const branchPrefix = opts.branchPrefix ?? 'corsec/hotfix';
  // Epoch seconds, not milliseconds — short enough to read in a branch name,
  // still unique to the second.
  const branchName = `${branchPrefix}/${Math.floor(Date.now() / 1000)}`;

  const matches = await loadMatches(opts.matchesPath);
  const consolidated = consolidateByPackage(matches);

  const packageJsonPath = join(opts.workingDir, 'package.json');
  const lockfilePath = join(opts.workingDir, 'package-lock.json');

  // Re-read the lockfile up front so the already-resolved check uses the
  // *current* installed version, not whatever Hunter saw. Falling back to an
  // empty map lets the caller still run the patcher without a lockfile
  // pre-populated — every package will then attempt install.
  let installedNow = new Map<string, string>();
  if (consolidated.length > 0) {
    try {
      installedNow = await loadInstalledVersions(packageJsonPath, lockfilePath);
    } catch {
      installedNow = new Map();
    }
  }

  // Classify each consolidated package before doing any I/O so we know whether
  // to create the branch at all. A branch with zero installs is just noise.
  const decisions = consolidated.map((pkg) => {
    const currentInstalled = installedNow.get(pkg.packageName) ?? pkg.installedVersion;
    let decision: 'no-fix' | 'already-resolved' | 'attempt';
    if (pkg.targetVersion === null) {
      decision = 'no-fix';
    } else if (isVersionInRange(currentInstalled, `>= ${pkg.targetVersion}`)) {
      decision = 'already-resolved';
    } else {
      decision = 'attempt';
    }
    return { pkg, currentInstalled, decision };
  });

  const willInstall = decisions.some((d) => d.decision === 'attempt');

  // Branch is created exactly once, BEFORE any install, and only when there's
  // a real install to attempt. No-fix-only or already-resolved-only sessions
  // produce results without touching git.
  if (willInstall) {
    const gitResult = await git(['checkout', '-b', branchName], opts.workingDir);
    if (gitResult.exitCode !== 0) {
      throw new Error(
        `applyPatches: git checkout -b ${branchName} failed (exit ${gitResult.exitCode}): ${gitResult.stderr.trim()}`,
      );
    }
  }

  const results: PatchResult[] = [];
  // Names of packages whose install exited 0; these share the upcoming test
  // run's outcome.
  const installedNames = new Set<string>();

  for (const { pkg, currentInstalled, decision } of decisions) {
    if (decision === 'no-fix') {
      results.push({
        packageName: pkg.packageName,
        previousVersion: currentInstalled,
        targetVersion: null,
        installedVersion: null,
        status: 'patch-failed-no-fix-available',
        relatedMatches: pkg.ghsaIds,
        testOutput: null,
        errorMessage: null,
      });
      continue;
    }

    if (decision === 'already-resolved') {
      results.push({
        packageName: pkg.packageName,
        previousVersion: currentInstalled,
        targetVersion: pkg.targetVersion,
        installedVersion: currentInstalled,
        status: 'skipped-already-resolved',
        relatedMatches: pkg.ghsaIds,
        testOutput: null,
        errorMessage: null,
      });
      continue;
    }

    // ^targetVersion (not =targetVersion): we want the most current release
    // in the patched-or-higher line, not the minimum patched version. This
    // makes the resulting PR less brittle when the package has moved several
    // patches/minors ahead of firstPatchedVersion.
    const installArgs = ['install', `${pkg.packageName}@^${pkg.targetVersion ?? ''}`];
    const installResult = await npm(installArgs, opts.workingDir);

    if (installResult.exitCode !== 0) {
      results.push({
        packageName: pkg.packageName,
        previousVersion: currentInstalled,
        targetVersion: pkg.targetVersion,
        installedVersion: null,
        status: 'patch-failed-install-error',
        relatedMatches: pkg.ghsaIds,
        testOutput: null,
        errorMessage:
          installResult.stderr.trim() ||
          `npm install exited with code ${installResult.exitCode}`,
      });
      // Critical: do NOT abort the session. The next package still gets its
      // shot.
      continue;
    }

    // Re-read the lockfile to learn what npm actually resolved to (which may
    // be higher than targetVersion thanks to the ^ range). If the lockfile
    // read fails, treat installedVersion as null but still consider the
    // install successful — npm exited 0.
    let newVersion: string | null = null;
    try {
      const updated = await loadInstalledVersions(packageJsonPath, lockfilePath);
      newVersion = updated.get(pkg.packageName) ?? null;
    } catch {
      newVersion = null;
    }

    results.push({
      packageName: pkg.packageName,
      previousVersion: currentInstalled,
      targetVersion: pkg.targetVersion,
      installedVersion: newVersion,
      // Placeholder; overwritten once the shared test run completes below.
      status: 'patched-tests-passed',
      relatedMatches: pkg.ghsaIds,
      testOutput: null,
      errorMessage: null,
    });
    installedNames.add(pkg.packageName);
  }

  if (installedNames.size > 0) {
    const testResult = await shell(opts.testCommand, opts.workingDir);
    const combined = testResult.stdout + testResult.stderr;
    const truncated = truncateTail(combined, TEST_OUTPUT_MAX_BYTES);
    const testStatus: PatchStatus =
      testResult.exitCode === 0 ? 'patched-tests-passed' : 'patched-tests-failed';

    for (const result of results) {
      if (installedNames.has(result.packageName)) {
        result.status = testStatus;
        result.testOutput = truncated;
      }
    }
  }

  results.sort((a, b) => a.packageName.localeCompare(b.packageName));

  const summary = {
    attempted: results.length,
    succeeded: results.filter((r) => r.status === 'patched-tests-passed').length,
    failedTests: results.filter((r) => r.status === 'patched-tests-failed').length,
    failedInstall: results.filter((r) => r.status === 'patch-failed-install-error').length,
    noFixAvailable: results.filter((r) => r.status === 'patch-failed-no-fix-available').length,
  };

  const session: PatchSession = { branchName, results, summary };
  await writeFile(opts.outputPath, JSON.stringify(session, null, 2), 'utf-8');
  return session;
}

async function loadMatches(matchesPath: string): Promise<MatchedThreat[]> {
  let raw: string;
  try {
    raw = await readFile(matchesPath, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`applyPatches: cannot read matches file ${matchesPath}: ${msg}`);
  }
  try {
    return JSON.parse(raw) as MatchedThreat[];
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`applyPatches: malformed JSON in matches file ${matchesPath}: ${msg}`);
  }
}

function consolidateByPackage(matches: MatchedThreat[]): ConsolidatedPatch[] {
  const byPackage = new Map<string, MatchedThreat[]>();
  for (const m of matches) {
    const arr = byPackage.get(m.packageName);
    if (arr) {
      arr.push(m);
    } else {
      byPackage.set(m.packageName, [m]);
    }
  }

  const out: ConsolidatedPatch[] = [];
  for (const [packageName, group] of byPackage) {
    // If any single match has no fix, we cannot safely patch the whole
    // package — the next install would still leave one of the CVEs open.
    const hasNullPatch = group.some((m) => m.patchedVersion === null);
    const ghsaIds = group.map((m) => m.ghsaId).sort();
    // All matches for the same package share installedVersion (it's the
    // lockfile entry), so picking the first is safe.
    const installedVersion = group[0]!.installedVersion;

    let targetVersion: string | null = null;
    if (!hasNullPatch) {
      const patches = group.map((m) => m.patchedVersion as string);
      targetVersion = pickHighest(patches);
    }

    out.push({ packageName, installedVersion, targetVersion, ghsaIds });
  }

  return out;
}

// Routes through shared/semverRange (CLAUDE.md hard rule: no direct semver
// calls in feature code). `isVersionInRange(a, '>= b')` is true iff a >= b.
function pickHighest(versions: string[]): string {
  let highest = versions[0]!;
  for (let i = 1; i < versions.length; i++) {
    const candidate = versions[i]!;
    if (!isVersionInRange(highest, `>= ${candidate}`)) {
      highest = candidate;
    }
  }
  return highest;
}

function truncateTail(s: string, maxBytes: number): string {
  // Operate on bytes so the "5 KB" budget is honoured even for non-ASCII
  // output. Slicing in the middle of a UTF-8 multi-byte sequence is
  // acceptable here — test output is almost always ASCII, and a few
  // replacement characters at the head of the truncated tail are preferable
  // to a length budget that quietly balloons.
  const buf = Buffer.from(s, 'utf-8');
  if (buf.length <= maxBytes) return s;
  return buf.subarray(buf.length - maxBytes).toString('utf-8');
}

// -- Default executors --------------------------------------------------------
// Only path that touches child_process. Tests inject all three executors and
// these functions are never reached.

function spawnWithArgs(binary: string, args: string[], cwd: string): Promise<ExecResult> {
  return spawnCapture(binary, args, {
    cwd,
    notFoundMessage: `applyPatches: '${binary}' binary not found on PATH. Install it and re-run.`,
  });
}

const defaultGit: GitExecutor = (args, cwd) => spawnWithArgs('git', args, cwd);
const defaultNpm: NpmExecutor = (args, cwd) => spawnWithArgs('npm', args, cwd);

// shell: true lets the user pass any test command string (including pipes,
// env vars, npm-script names) without us having to parse argv. Matches the
// way humans actually invoke their test suites.
//
// No notFoundMessage: under a shell there is no ENOENT to translate — an
// unknown command is the shell's own exit 127, which the caller already reads
// as a failed test run.
const defaultShell: ShellExecutor = (command, cwd) =>
  spawnCapture(command, [], { cwd, shell: true });
