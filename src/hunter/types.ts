// Ecosystem and Severity unions are grounded in what the fixture and query actually return.
// Extend if a new ecosystem or severity level is added to GitHub's schema.

// The runtime list is the source of truth and the type is derived from it, so
// the two cannot drift. Before this, the union was the type-level truth while
// two byte-identical `isEcosystem` guards (run.ts, orchestrate.ts) and two
// copies of the message 'must be one of NPM, PIP, MAVEN' were the runtime
// truth, with nothing linking them — adding 'RUBYGEMS' to the union compiled
// clean, both option types accepted it and fetchAdvisories passed it to
// GraphQL, but both CLIs rejected it with a message still naming three. A value
// the type system called legal was unreachable from every entry point, with no
// compiler signal.
//
// This is why the guard lives here rather than in src/shared/: co-location with
// the union is the point.
export const ECOSYSTEMS = ['NPM', 'PIP', 'MAVEN'] as const;

export type Ecosystem = (typeof ECOSYSTEMS)[number];

export function isEcosystem(value: string): value is Ecosystem {
  return (ECOSYSTEMS as readonly string[]).includes(value);
}

export type Severity = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

// One installed package × one vulnerable range that it falls within.
// Multi-node advisories produce one MatchedThreat per matching node, not one per advisory.
export interface MatchedThreat {
  ghsaId: string;
  packageName: string;
  installedVersion: string;
  vulnerableRange: string;
  patchedVersion: string | null;
  severity: Severity;
  cvssScore: number | null;
  summary: string;
}

export interface Vulnerability {
  package: {
    name: string;
    ecosystem: Ecosystem;
  };
  vulnerableVersionRange: string;
  // null when the advisory has no patched version yet
  firstPatchedVersion: { identifier: string } | null;
}

export interface Advisory {
  ghsaId: string;
  summary: string;
  severity: Severity;
  // null for advisories that have no CVSS score assigned
  cvss: { score: number } | null;
  vulnerabilities: {
    // May be empty when no packages in the requested ecosystem are affected.
    // Callers must not assume at least one node is present.
    nodes: Vulnerability[];
  };
}
