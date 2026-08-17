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
import type { AdvisoryRecording } from '../src/hunter/advisorySource.js';
import { ECOSYSTEMS, isEcosystem } from '../src/hunter/types.js';

const { values } = parseArgs({
  options: {
    days: { type: 'string' },
    output: { type: 'string' },
    ecosystem: { type: 'string' },
  },
  strict: true,
});

const days = Number(values.days ?? '30');
const ecosystemRaw = values.ecosystem ?? 'NPM';

// This script lives outside tsconfig's `include`, so it is not covered by
// `npm run typecheck`. It used to paper over that with an unchecked
// `as Ecosystem` cast, which meant `--ecosystem rubygems` produced a variable
// statically typed Ecosystem holding a value the type does not contain — and
// then wrote it into a recording as though it were real.
if (!isEcosystem(ecosystemRaw)) {
  console.error(`Error: --ecosystem must be one of ${ECOSYSTEMS.join(', ')}`);
  process.exit(1);
}
const ecosystem = ecosystemRaw;

// Refuse to overwrite the shared replay fixture with a different ecosystem.
// The old default sent every run to this exact path, so
// `--ecosystem PIP` silently replaced the NPM fixture that run-local.sh reads
// and the next local run came back green and empty.
const DEFAULT_OUTPUT = 'fixtures/recorded-advisories.json';
const output = values.output ?? DEFAULT_OUTPUT;
if (output === DEFAULT_OUTPUT && ecosystem !== 'NPM') {
  console.error(
    `Error: ${DEFAULT_OUTPUT} is the NPM replay fixture that scripts/run-local.sh reads.\n` +
      `Recording ${ecosystem} advisories over it would make local runs report a false\n` +
      `all-clear. Pass an explicit --output path instead.`,
  );
  process.exit(1);
}

const sinceISO = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

const advisories = await fetchRecentAdvisories(sinceISO, ecosystem);

// Keep only advisories that actually name a package in this ecosystem. The API
// returns advisories whose vulnerabilities[] is empty once the ecosystem filter
// is applied server-side; those are pure noise in a replay fixture.
//
// Note this makes a recording NOT a byte-exact transcript of the live response
// — the live path deliberately keeps empty-node advisories. See the comment on
// AdvisoryRecording.advisories.
const useful = advisories.filter((a) => a.vulnerabilities.nodes.length > 0);

// Written as an envelope, not a bare array: the payload alone cannot say which
// ecosystem or window it came from, and replaying it against the wrong one used
// to yield a confident all-clear rather than an error.
const recording: AdvisoryRecording = {
  recordedAt: new Date().toISOString(),
  sinceISO,
  ecosystem,
  advisories: useful,
};

await writeFile(output, JSON.stringify(recording, null, 2) + '\n', 'utf-8');

const packages = new Set(
  useful.flatMap((a) => a.vulnerabilities.nodes.map((n) => n.package.name)),
);

console.log(`Recorded ${useful.length} advisories (from ${advisories.length} returned)`);
console.log(`  window:    since ${sinceISO} (${days}d)`);
console.log(`  ecosystem: ${ecosystem}`);
console.log(`  packages:  ${packages.size} distinct`);
console.log(`  written:   ${output}`);
