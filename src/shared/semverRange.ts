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
