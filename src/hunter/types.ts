// Ecosystem and Severity unions are grounded in what the fixture and query actually return.
// Extend if a new ecosystem or severity level is added to GitHub's schema.
export type Ecosystem = 'NPM' | 'PIP' | 'MAVEN';
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
