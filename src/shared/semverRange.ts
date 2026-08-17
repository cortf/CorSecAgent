import { satisfies, validRange, valid } from 'semver';

/**
 * Converts a GitHub Advisory-style range (comma-separated) to the
 * space-separated form that semver.satisfies() accepts. Also trims and
 * collapses internal whitespace.
 *
 * Example: ">= 4.17.0, < 4.17.21"  →  ">= 4.17.0 < 4.17.21"
 */
export function normalizeRange(range: string): string {
  return range
    .split(',')
    .map(part => part.trim())
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Returns true if `version` satisfies `range`.
 *
 * Range format: GitHub Advisory comma-separated (">= 1.0.0, < 2.0.0") or
 * native semver space-separated (">= 1.0.0 < 2.0.0"). Both are normalized
 * before evaluation.
 *
 * Pre-release behavior: a pre-release version (e.g. "1.0.0-alpha.1") will NOT
 * match a range like ">= 1.0.0" unless the range itself contains a pre-release
 * comparator sharing the same [major, minor, patch] tuple. This is semver's
 * default and is intentionally preserved — it prevents a pre-release of a
 * later version from being falsely flagged as vulnerable when the range was
 * written against stable releases only.
 *
 * @throws {Error} if `range` is not a valid semver range expression.
 * @returns false (not throw) if `version` is not a valid semver string, because
 *   lockfiles occasionally contain non-semver strings (git SHAs, file: refs)
 *   that should be silently skipped rather than crashing the pipeline.
 */
export function isVersionInRange(version: string, range: string): boolean {
  const normalized = normalizeRange(range);

  if (validRange(normalized) === null) {
    throw new Error(`Invalid semver range: "${range}" (normalized: "${normalized}")`);
  }

  if (valid(version) === null) {
    return false;
  }

  return satisfies(version, normalized);
}

/**
 * Returns true if `version` is at least `minimum`. Both arguments are
 * *versions*, not ranges.
 *
 * Use this instead of `isVersionInRange(v, \`>= ${m}\`)`. That idiom concatenates
 * a value into a range expression, which inherits `isVersionInRange`'s
 * asymmetric contract: it **throws** on an unparseable range but returns false
 * on an unparseable version — so an unparseable *version* spliced into the
 * range position became a throw.
 *
 * That was a live crash path, not a hypothetical. `patchedVersion` comes
 * straight from the GitHub Advisory API's `firstPatchedVersion.identifier` and
 * is not validated semver; `1.2.3.RELEASE` is idiomatic Maven versioning and
 * MAVEN is an accepted `--ecosystem`. One such advisory threw out of
 * `pickHighest` → `consolidateByPackage` → `applyPatches`, and the orchestrator
 * turned the entire patch stage into a synthetic empty session — so every
 * *other* package silently lost its patch too.
 *
 * @returns false (not throw) if either argument is not valid semver, matching
 *   this module's existing lenient-on-versions contract.
 */
export function isAtLeast(version: string, minimum: string): boolean {
  if (valid(version) === null || valid(minimum) === null) {
    return false;
  }
  // Routed through satisfies rather than semver.gte so pre-release handling
  // stays identical to isVersionInRange: "2.0.0-alpha" does NOT satisfy
  // ">=1.0.0", whereas gte() would say it does.
  return satisfies(version, `>=${minimum}`);
}

/**
 * Returns true if `version` is a valid semver string and can therefore take
 * part in a comparison. Callers that must pick between candidates need this to
 * distinguish "definitely lower" from "not comparable at all" — `isAtLeast`
 * returns false for both.
 */
export function isComparableVersion(version: string): boolean {
  return valid(version) !== null;
}
