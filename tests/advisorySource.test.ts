import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  fileAdvisoryFetcher,
  parseAdvisoryRecording,
  type AdvisoryRecording,
} from '../src/hunter/advisorySource.js';

// The real replay artifact, loaded at module level per the CLAUDE.md pattern.
const RECORDING_PATH = fileURLToPath(
  new URL('../fixtures/recorded-advisories.json', import.meta.url),
);
const recording = JSON.parse(
  readFileSync(RECORDING_PATH, 'utf-8'),
) as AdvisoryRecording;

// Write a payload to a scratch file so the fetcher's real read path is
// exercised — this module is all about a file on disk, so stubbing the read
// would test nothing that matters.
async function withTempFile(
  contents: string,
  fn: (path: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'advisory-source-'));
  const path = join(dir, 'recording.json');
  await writeFile(path, contents, 'utf-8');
  try {
    await fn(path);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const MINIMAL: AdvisoryRecording = {
  recordedAt: '2026-01-01T00:00:00.000Z',
  sinceISO: '2025-12-02T00:00:00.000Z',
  ecosystem: 'NPM',
  advisories: [
    {
      ghsaId: 'GHSA-test-0001',
      summary: 'test advisory',
      severity: 'HIGH',
      cvss: { score: 7.5 },
      vulnerabilities: {
        nodes: [
          {
            package: { name: 'lodash', ecosystem: 'NPM' },
            vulnerableVersionRange: '< 4.17.21',
            firstPatchedVersion: { identifier: '4.17.21' },
          },
        ],
      },
    },
  ],
};

describe('parseAdvisoryRecording — well-formed envelope', () => {
  it('returns the envelope with its advisories intact', () => {
    const parsed = parseAdvisoryRecording(JSON.stringify(MINIMAL), '/x.json');
    expect(parsed.ecosystem).toBe('NPM');
    expect(parsed.advisories).toHaveLength(1);
  });
});

describe('parseAdvisoryRecording — pre-envelope format (should throw)', () => {
  it('throws a migration message naming the file when handed a bare advisory array', () => {
    // Without this branch the field reads would fail on undefined.filter and
    // say nothing about why.
    const call = () => parseAdvisoryRecording('[]', '/legacy.json');
    expect(call).toThrow(/bare advisory array/);
    expect(call).toThrow('/legacy.json');
  });

  it('tells the migrator to preserve the array rather than re-record it', () => {
    // Re-recording would roll the live query's 100-advisory window forward and
    // drop the packages the sandbox pins.
    expect(() => parseAdvisoryRecording('[]', '/legacy.json')).toThrow(
      /rather than re-recording/,
    );
  });
});

describe('parseAdvisoryRecording — invalid input (should throw)', () => {
  it('throws naming the file when the JSON is malformed', () => {
    const call = () => parseAdvisoryRecording('{not json', '/broken.json');
    expect(call).toThrow(/malformed JSON/);
    expect(call).toThrow('/broken.json');
  });

  it('throws naming the missing field when ecosystem is absent', () => {
    const { ecosystem: _drop, ...rest } = MINIMAL;
    const call = () => parseAdvisoryRecording(JSON.stringify(rest), '/no-eco.json');
    expect(call).toThrow(/"ecosystem"/);
    expect(call).toThrow('/no-eco.json');
  });

  it('throws naming the missing field when advisories is absent', () => {
    const { advisories: _drop, ...rest } = MINIMAL;
    const call = () => parseAdvisoryRecording(JSON.stringify(rest), '/no-adv.json');
    expect(call).toThrow(/"advisories"/);
    expect(call).toThrow('/no-adv.json');
  });
});

describe('fileAdvisoryFetcher — matching ecosystem', () => {
  it('returns every recorded advisory without filtering', async () => {
    await withTempFile(JSON.stringify(MINIMAL), async (path) => {
      const advisories = await fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'NPM');
      expect(advisories).toHaveLength(1);
      expect(advisories[0]?.vulnerabilities.nodes).toHaveLength(1);
    });
  });
});

describe('fileAdvisoryFetcher — ecosystem mismatch (should throw, not report all-clear)', () => {
  // The silent-failure mode this whole module exists to remove: the old
  // fetcher filtered client-side, so replaying an NPM recording under PIP left
  // every advisory with an empty node list, matchCount was 0, and the
  // orchestrator printed "No vulnerabilities found — exiting successfully".
  it('throws rather than returning advisories with empty node lists', async () => {
    await withTempFile(JSON.stringify(MINIMAL), async (path) => {
      await expect(fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'PIP')).rejects.toThrow(
        /ecosystem mismatch/,
      );
    });
  });

  it('names both the recorded and the requested ecosystem, and the file', async () => {
    await withTempFile(JSON.stringify(MINIMAL), async (path) => {
      const run = fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'MAVEN');
      await expect(run).rejects.toThrow(/captured for NPM/);
      await expect(fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'MAVEN')).rejects.toThrow(
        /requested MAVEN/,
      );
      await expect(fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'MAVEN')).rejects.toThrow(
        path,
      );
    });
  });
});

describe('fileAdvisoryFetcher — missing file (should throw)', () => {
  it('throws naming the path that could not be read', async () => {
    const missing = join(tmpdir(), `definitely-absent-${Date.now()}.json`);
    await expect(fileAdvisoryFetcher(missing)('2026-01-01T00:00:00.000Z', 'NPM'))
      .rejects.toThrow(missing);
  });
});

describe('fileAdvisoryFetcher — --since alongside a recording', () => {
  it('warns that the window is ignored instead of silently disagreeing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await withTempFile(JSON.stringify(MINIMAL), async (path) => {
        await fileAdvisoryFetcher(path)('2020-01-01T00:00:00.000Z', 'NPM');
      });
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('--since is ignored'));
    } finally {
      warn.mockRestore();
    }
  });

  it('stays quiet when the requested window matches the recording', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await withTempFile(JSON.stringify(MINIMAL), async (path) => {
        await fileAdvisoryFetcher(path)(MINIMAL.sinceISO, 'NPM');
      });
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});

describe('Recorded-advisory fixture — fixtures/recorded-advisories.json', () => {
  // This artifact is load-bearing in a non-obvious way: it carries advisories
  // for exactly the three packages scripts/setup-sandbox.sh pins, out of 14
  // distinct packages. Re-recording it would roll the live query's 100-advisory
  // window forward and most likely drop all three, turning run-local.sh into a
  // silent zero-match run. These assertions are the tripwire for that.
  it('is an envelope carrying its own ecosystem and capture window', () => {
    expect(recording.ecosystem).toBe('NPM');
    expect(recording.recordedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(recording.sinceISO).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('still carries the 21 advisories the local end-to-end run replays', () => {
    expect(recording.advisories).toHaveLength(21);
  });

  it('still covers the three packages the sandbox pins', () => {
    const packages = new Set(
      recording.advisories.flatMap((a) =>
        a.vulnerabilities.nodes.map((n) => n.package.name),
      ),
    );
    for (const pinned of ['crypto-js', 'dompurify', 'hono']) {
      expect(packages).toContain(pinned);
    }
  });

  it('replays through the real fetcher under NPM', async () => {
    const advisories = await fileAdvisoryFetcher(RECORDING_PATH)(
      recording.sinceISO,
      'NPM',
    );
    expect(advisories).toHaveLength(21);
  });
});
