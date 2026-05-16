import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { fetchRecentAdvisories } from './fetchAdvisories.js';
import { loadInstalledVersions, matchAdvisoriesAgainstDeps } from './matchDependencies.js';
import type { Advisory, Ecosystem } from './types.js';

// Injecting the advisory-fetcher as an optional last param keeps network I/O out
// of tests without coupling test code to module internals. When omitted, the real
// fetchRecentAdvisories is used — which requires GITHUB_TOKEN.
type AdvisoryFetcher = (sinceISO: string, ecosystem: Ecosystem) => Promise<Advisory[]>;

export interface RunHunterOptions {
  sinceISO: string;
  ecosystem: Ecosystem;
  packageJsonPath: string;
  lockfilePath: string;
  outputPath: string;
}

export async function runHunter(
  opts: RunHunterOptions,
  fetcher: AdvisoryFetcher = fetchRecentAdvisories,
): Promise<{ matchCount: number }> {
  const [advisories, installed] = await Promise.all([
    fetcher(opts.sinceISO, opts.ecosystem),
    loadInstalledVersions(opts.packageJsonPath, opts.lockfilePath),
  ]);

  const matches = matchAdvisoriesAgainstDeps(advisories, installed);
  await writeFile(opts.outputPath, JSON.stringify(matches, null, 2), 'utf-8');
  return { matchCount: matches.length };
}

function isEcosystem(s: string): s is Ecosystem {
  return s === 'NPM' || s === 'PIP' || s === 'MAVEN';
}

// Only runs when this file is executed directly (e.g. npx tsx src/hunter/run.ts).
// The import.meta.url check prevents CLI side effects when tests import runHunter.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const defaultSince = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const { values } = parseArgs({
    options: {
      since: { type: 'string' },
      ecosystem: { type: 'string' },
      'package-json': { type: 'string' },
      lockfile: { type: 'string' },
      output: { type: 'string' },
    },
    strict: true,
  });

  const outputPath = values.output;
  if (outputPath === undefined) {
    console.error('Error: --output <path> is required');
    process.exit(1);
  }

  const rawEcosystem = values.ecosystem ?? 'NPM';
  if (!isEcosystem(rawEcosystem)) {
    console.error('Error: --ecosystem must be one of NPM, PIP, MAVEN');
    process.exit(1);
  }

  runHunter(
    {
      sinceISO: values.since ?? defaultSince,
      ecosystem: rawEcosystem,
      packageJsonPath: values['package-json'] ?? './package.json',
      lockfilePath: values.lockfile ?? './package-lock.json',
      outputPath,
    },
  )
    .then(({ matchCount }) => {
      console.log(`Found ${matchCount} matches, written to ${outputPath}`);
    })
    .catch((err: unknown) => {
      console.error('Hunter failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    });
}
