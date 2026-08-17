// Record a real GitHub Advisory API response to disk so end-to-end runs can be
// replayed deterministically (`orchestrate --advisories-file`).
//
// Why this exists: the live query is capped at the 100 most recently published
// advisories, ordered by publishedAt DESC. That window rolls forward constantly,
// so a sandbox pinned to today's vulnerable packages silently stops matching
// after a few weeks. Recording the payload freezes the scenario, and removes the
// GITHUB_TOKEN requirement from every subsequent test run.
//
// Usage:
//   GITHUB_TOKEN=$(gh auth token) npx tsx scripts/record-advisories.ts \
//     --days 30 --output fixtures/recorded-advisories.json

import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { fetchRecentAdvisories } from '../src/hunter/fetchAdvisories.js';
import type { Ecosystem } from '../src/hunter/types.js';

const { values } = parseArgs({
  options: {
    days: { type: 'string' },
    output: { type: 'string' },
    ecosystem: { type: 'string' },
  },
  strict: true,
});

const days = Number(values.days ?? '30');
const output = values.output ?? 'fixtures/recorded-advisories.json';
const ecosystem = (values.ecosystem ?? 'NPM') as Ecosystem;

const sinceISO = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

const advisories = await fetchRecentAdvisories(sinceISO, ecosystem);

// Keep only advisories that actually name a package in this ecosystem. The API
// returns advisories whose vulnerabilities[] is empty once the ecosystem filter
// is applied server-side; those are pure noise in a replay fixture.
const useful = advisories.filter((a) => a.vulnerabilities.nodes.length > 0);

await writeFile(output, JSON.stringify(useful, null, 2), 'utf-8');

const packages = new Set(
  useful.flatMap((a) => a.vulnerabilities.nodes.map((n) => n.package.name)),
);

console.log(`Recorded ${useful.length} advisories (from ${advisories.length} returned)`);
console.log(`  window:    since ${sinceISO} (${days}d)`);
console.log(`  ecosystem: ${ecosystem}`);
console.log(`  packages:  ${packages.size} distinct`);
console.log(`  written:   ${output}`);
