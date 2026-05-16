import { describe, it, expect } from 'vitest';
import { isVersionInRange, normalizeRange } from '../src/shared/semverRange.js';

describe('normalizeRange', () => {
  it('passes through a simple range unchanged', () => {
    expect(normalizeRange('< 1.2.3')).toBe('< 1.2.3');
  });

  it('converts comma-separated to space-separated', () => {
    expect(normalizeRange('>= 1.0.0, < 2.0.0')).toBe('>= 1.0.0 < 2.0.0');
  });

  it('trims leading and trailing whitespace', () => {
    expect(normalizeRange('  >= 1.0.0, < 2.0.0  ')).toBe('>= 1.0.0 < 2.0.0');
  });

  it('collapses internal whitespace', () => {
    expect(normalizeRange('>=  1.0.0,  <  2.0.0')).toBe('>= 1.0.0 < 2.0.0');
  });

  it('handles a three-part compound range', () => {
    expect(normalizeRange('>= 1.0.0, >= 1.1.0, < 2.0.0')).toBe('>= 1.0.0 >= 1.1.0 < 2.0.0');
  });
});

describe('isVersionInRange — simple ranges', () => {
  it('matches a version strictly below an exclusive upper bound', () => {
    expect(isVersionInRange('1.2.2', '< 1.2.3')).toBe(true);
  });

  it('does not match a version equal to an exclusive upper bound', () => {
    expect(isVersionInRange('1.2.3', '< 1.2.3')).toBe(false);
  });

  it('does not match a version above an exclusive upper bound', () => {
    expect(isVersionInRange('1.2.4', '< 1.2.3')).toBe(false);
  });

  it('matches a version equal to an inclusive lower bound', () => {
    expect(isVersionInRange('1.0.0', '>= 1.0.0')).toBe(true);
  });

  it('does not match a version below an inclusive lower bound', () => {
    expect(isVersionInRange('0.9.9', '>= 1.0.0')).toBe(false);
  });
});

describe('isVersionInRange — compound ranges (GitHub Advisory style)', () => {
  const range = '>= 1.0.0, < 2.0.0';

  it('matches inside the range', () => {
    expect(isVersionInRange('1.5.0', range)).toBe(true);
  });

  it('matches at the inclusive lower bound', () => {
    expect(isVersionInRange('1.0.0', range)).toBe(true);
  });

  it('does not match below the lower bound', () => {
    expect(isVersionInRange('0.9.9', range)).toBe(false);
  });

  it('does not match at the exclusive upper bound', () => {
    expect(isVersionInRange('2.0.0', range)).toBe(false);
  });

  it('does not match above the upper bound', () => {
    expect(isVersionInRange('2.1.0', range)).toBe(false);
  });
});

describe('isVersionInRange — wildcard', () => {
  it('matches any stable version against *', () => {
    expect(isVersionInRange('3.5.1', '*')).toBe(true);
  });

  it('matches version 0.0.1 against *', () => {
    expect(isVersionInRange('0.0.1', '*')).toBe(true);
  });
});

describe('isVersionInRange — pre-release versions', () => {
  it('does not match a pre-release against a stable-only range (semver default)', () => {
    // "1.0.0-alpha.1" is not considered to satisfy ">= 1.0.0" because the
    // range has no pre-release comparator for the 1.0.0 tuple.
    expect(isVersionInRange('1.0.0-alpha.1', '>= 1.0.0')).toBe(false);
  });

  it('matches a pre-release when the range explicitly includes pre-releases for that tuple', () => {
    expect(isVersionInRange('1.0.0-alpha.1', '>= 1.0.0-alpha.0, < 1.0.0')).toBe(true);
  });

  it('matches a pre-release between two pre-release bounds of the same tuple', () => {
    expect(isVersionInRange('1.0.0-beta.2', '>= 1.0.0-alpha.1, < 1.0.0-rc.1')).toBe(true);
  });

  it('does not match a pre-release outside its tuple bounds', () => {
    // 2.0.0-beta.1 would not satisfy a range written for the 1.x.x pre-release
    expect(isVersionInRange('2.0.0-beta.1', '>= 1.0.0-alpha.0, < 1.0.0')).toBe(false);
  });
});

describe('isVersionInRange — invalid version strings (should return false, not throw)', () => {
  it('returns false for a git SHA', () => {
    expect(isVersionInRange('abc123def456abc1', '< 2.0.0')).toBe(false);
  });

  it('returns false for a file: reference', () => {
    expect(isVersionInRange('file:../local-pkg', '< 2.0.0')).toBe(false);
  });

  it('returns false for a URL version string', () => {
    expect(isVersionInRange('https://example.com/pkg.tgz', '< 2.0.0')).toBe(false);
  });

  it('returns false for an empty string', () => {
    expect(isVersionInRange('', '< 2.0.0')).toBe(false);
  });

  it('returns false for a plain word with no dots', () => {
    expect(isVersionInRange('latest', '>= 1.0.0')).toBe(false);
  });
});

describe('isVersionInRange — invalid range strings (should throw)', () => {
  it('throws for a nonsense range string', () => {
    expect(() => isVersionInRange('1.0.0', '>= !!!')).toThrow(/Invalid semver range/);
  });

  it('throws for a range that is just a bare word', () => {
    expect(() => isVersionInRange('1.0.0', 'not-a-range')).toThrow(/Invalid semver range/);
  });

  it('error message includes the original range string', () => {
    expect(() => isVersionInRange('1.0.0', '>= !!!')).toThrow('>= !!!');
  });
});

describe('GitHub Advisory fixture — electerm (>= 3.0.6, <= 3.8.8, patched at 3.9.0)', () => {
  const range = '>= 3.0.6, <= 3.8.8';

  it('matches a version inside the vulnerable range', () => {
    expect(isVersionInRange('3.5.0', range)).toBe(true);
  });

  it('matches the inclusive lower bound', () => {
    expect(isVersionInRange('3.0.6', range)).toBe(true);
  });

  it('matches the inclusive upper bound', () => {
    expect(isVersionInRange('3.8.8', range)).toBe(true);
  });

  it('does not match a version just below the lower bound', () => {
    expect(isVersionInRange('3.0.5', range)).toBe(false);
  });

  it('does not match the patched version (3.9.0)', () => {
    expect(isVersionInRange('3.9.0', range)).toBe(false);
  });

  it('does not match a version well above the upper bound', () => {
    expect(isVersionInRange('4.0.0', range)).toBe(false);
  });
});
