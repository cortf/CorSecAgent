import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { fetchRecentAdvisories } from '../src/hunter/fetchAdvisories.js';
import type { Advisory } from '../src/hunter/types.js';

// Load the recorded fixture. The fixture was captured without cvss in the query,
// so we normalize each node by adding cvss: null — matching what the live API
// returns for advisories that have no CVSS score.
const raw = JSON.parse(
  readFileSync(new URL('../fixtures/github-advisory-api.json', import.meta.url), 'utf-8'),
) as { data: { securityAdvisories: { nodes: Record<string, unknown>[] } } };

const fixtureNodes: Advisory[] = raw.data.securityAdvisories.nodes.map(node => ({
  ...node,
  cvss: null,
})) as Advisory[];

function makeClient(response: unknown) {
  return vi.fn().mockResolvedValue(response);
}

describe('fetchRecentAdvisories — returns typed Advisory[]', () => {
  it('returns an array whose length and first ghsaId match the fixture', async () => {
    const client = makeClient({ securityAdvisories: { nodes: fixtureNodes } });
    const result = await fetchRecentAdvisories('2024-01-03T21:00:00Z', 'NPM', client);
    expect(result).toHaveLength(fixtureNodes.length);
    expect(result[0]?.ghsaId).toBe('GHSA-cfph-4qqh-w828');
  });
});

describe('fetchRecentAdvisories — parameter pass-through', () => {
  it('passes sinceISO as the $since variable to the graphql client', async () => {
    const client = makeClient({ securityAdvisories: { nodes: [] } });
    await fetchRecentAdvisories('2024-06-01T00:00:00Z', 'NPM', client);
    expect(client).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ since: '2024-06-01T00:00:00Z' }),
    );
  });

  it('passes ecosystem as the $ecosystem variable to the graphql client', async () => {
    const client = makeClient({ securityAdvisories: { nodes: [] } });
    await fetchRecentAdvisories('2024-01-03T21:00:00Z', 'PIP', client);
    expect(client).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ ecosystem: 'PIP' }),
    );
  });
});

describe('fetchRecentAdvisories — missing GITHUB_TOKEN (no injected client)', () => {
  it('throws with a message naming GITHUB_TOKEN when the env var is absent', async () => {
    const saved = process.env['GITHUB_TOKEN'];
    delete process.env['GITHUB_TOKEN'];
    try {
      await expect(
        fetchRecentAdvisories('2024-01-03T21:00:00Z', 'NPM'),
      ).rejects.toThrow('GITHUB_TOKEN');
    } finally {
      if (saved !== undefined) {
        process.env['GITHUB_TOKEN'] = saved;
      }
    }
  });
});

describe('fetchRecentAdvisories — empty response', () => {
  it('returns an empty array (not undefined or null) when the API returns zero advisories', async () => {
    const client = makeClient({ securityAdvisories: { nodes: [] } });
    const result = await fetchRecentAdvisories('2024-01-03T21:00:00Z', 'NPM', client);
    expect(result).toEqual([]);
    expect(Array.isArray(result)).toBe(true);
  });
});

describe('GitHub Advisory fixture — GHSA-f8mp-x433-5wpf (multi-node wrangler advisory)', () => {
  it('returns both vulnerability nodes intact in vulnerabilities.nodes', async () => {
    const client = makeClient({ securityAdvisories: { nodes: fixtureNodes } });
    const result = await fetchRecentAdvisories('2024-01-03T21:00:00Z', 'NPM', client);

    const advisory = result.find(a => a.ghsaId === 'GHSA-f8mp-x433-5wpf');
    expect(advisory).toBeDefined();

    const nodes = advisory!.vulnerabilities.nodes;
    expect(nodes).toHaveLength(2);

    const ranges = nodes.map(n => n.vulnerableVersionRange);
    expect(ranges).toContain('>= 2.0.0, < 2.20.2');
    expect(ranges).toContain('>= 3.0.0, < 3.19.0');
  });
});

describe('fetchRecentAdvisories — advisories with zero NPM vulnerabilities', () => {
  it('returns advisories with empty vulnerabilities.nodes without filtering them out', async () => {
    const client = makeClient({ securityAdvisories: { nodes: fixtureNodes } });
    const result = await fetchRecentAdvisories('2024-01-03T21:00:00Z', 'NPM', client);

    const zeroVulnAdvisories = result.filter(a => a.vulnerabilities.nodes.length === 0);
    expect(zeroVulnAdvisories.length).toBeGreaterThan(0);
  });
});
