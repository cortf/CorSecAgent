import { readFile } from 'fs/promises';
import type { Advisory, MatchedThreat } from './types.js';
import { isVersionInRange } from '../shared/semverRange.js';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface LockfileEntry {
  version?: string;
}

interface NpmLockfile {
  // npm v7+ lockfile format: packages keyed by "" (root) or "node_modules/<name>"
  packages?: Record<string, LockfileEntry>;
}

// Only direct dependencies (union of dependencies + devDependencies in package.json)
// are resolved. Transitive dependencies present in the lockfile but absent from
// package.json are intentionally excluded — transitive coverage is planned for a
// later slice.
export async function loadInstalledVersions(
  packageJsonPath: string,
  lockfilePath: string,
): Promise<Map<string, string>> {
  let pkgRaw: string;
  let lockRaw: string;

  try {
    [pkgRaw, lockRaw] = await Promise.all([
      readFile(packageJsonPath, 'utf-8'),
      readFile(lockfilePath, 'utf-8'),
    ]);
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    throw new Error(`Cannot read ${e.path ?? 'file'}: ${e.message}`);
  }

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(pkgRaw) as PackageJson;
  } catch {
    throw new Error(`Malformed JSON in ${packageJsonPath}`);
  }

  let lock: NpmLockfile;
  try {
    lock = JSON.parse(lockRaw) as NpmLockfile;
  } catch {
    throw new Error(`Malformed JSON in ${lockfilePath}`);
  }

  // Iterate the declared names and index into the lockfile, rather than
  // scanning every lockfile entry and filtering it against a declared-names Set.
  //
  // Direct dependencies are hoisted to the lockfile root, so a declared name IS
  // the key: `node_modules/<name>`. Scanning the other way round meant
  // reconstructing names by stripping one 'node_modules/' prefix, which on a
  // real lockfile (219 entries here, 30 of them nested) built and probed
  // meaningless strings like "vite/node_modules/@types/node" — questions with
  // no answer, since npm names cannot contain '/' outside a scope prefix. 209
  // of 219 entries were examined only to be discarded.
  //
  // Indexing in also makes the direct-deps-only scope visible in the shape of
  // the code rather than emergent from a filter.
  const declared = [
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
  ];

  const packages = lock.packages ?? {};
  const result = new Map<string, string>();
  for (const name of declared) {
    const version = packages[`node_modules/${name}`]?.version;
    if (version !== undefined) {
      result.set(name, version);
    }
  }

  return result;
}

export function matchAdvisoriesAgainstDeps(
  advisories: Advisory[],
  installed: Map<string, string>,
): MatchedThreat[] {
  const matches: MatchedThreat[] = [];

  for (const advisory of advisories) {
    for (const vuln of advisory.vulnerabilities.nodes) {
      const installedVersion = installed.get(vuln.package.name);
      if (installedVersion === undefined) continue;

      if (!isVersionInRange(installedVersion, vuln.vulnerableVersionRange)) continue;

      matches.push({
        ghsaId: advisory.ghsaId,
        packageName: vuln.package.name,
        installedVersion,
        vulnerableRange: vuln.vulnerableVersionRange,
        patchedVersion: vuln.firstPatchedVersion?.identifier ?? null,
        severity: advisory.severity,
        cvssScore: advisory.cvss?.score ?? null,
        summary: advisory.summary,
      });
    }
  }

  // Stable sort ensures callers get the same order regardless of API response ordering.
  matches.sort((a, b) => {
    if (a.ghsaId !== b.ghsaId) return a.ghsaId.localeCompare(b.ghsaId);
    return a.packageName.localeCompare(b.packageName);
  });

  return matches;
}
