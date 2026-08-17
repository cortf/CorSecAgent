// Ownership of the advisory-replay contract.
//
// Before this module the contract was spread across four files and one
// shapeless artifact: run.ts and orchestrate.ts each respelled the fetcher
// type, orchestrate.ts re-implemented the server-side ecosystem filter
// client-side, scripts/record-advisories.ts held the recording rule, and
// scripts/run-local.sh held the path. The recording itself was a bare
// Advisory[] carrying no ecosystem, no window and no capture timestamp.
//
// That combination had a live silent-failure mode one command away. Running
// with `--ecosystem PIP --advisories-file <an NPM recording>` made every node
// fail the client-side filter, so 21 advisories arrived with empty node lists,
// matchCount was 0, and the orchestrator printed "No vulnerabilities found —
// exiting successfully" and exited 0. A security pipeline reported all-clear
// because a flag and a fixture disagreed. Worse, the recorder defaulted its
// output to the exact path run-local.sh reads, so
// `npx tsx scripts/record-advisories.ts --ecosystem PIP` silently overwrote the
// NPM replay fixture and the next local run was green and empty.
//
// The envelope fixes that at the root: the artifact carries its own provenance
// and the fetcher THROWS on a mismatch instead of quietly filtering to nothing.

import { readFile } from 'node:fs/promises';
import type { Advisory, Ecosystem } from './types.js';

// The seam every advisory consumer injects. Declared once, here, rather than
// respelled at each call site.
export type AdvisoryFetcher = (
  sinceISO: string,
  ecosystem: Ecosystem,
) => Promise<Advisory[]>;

// A recorded advisory payload plus the provenance needed to know whether it is
// the right payload for the run that is about to replay it.
export interface AdvisoryRecording {
  // When the recording was captured (ISO 8601).
  recordedAt: string;
  // The `publishedSince` window the capture used.
  sinceISO: string;
  // The ecosystem the capture filtered on. A run replaying this recording must
  // use the same one.
  ecosystem: Ecosystem;
  // Advisories exactly as the GraphQL query returned them for that ecosystem,
  // with one documented exception: the recorder drops advisories whose
  // `vulnerabilities.nodes` came back empty. Those are advisories that name no
  // package in the requested ecosystem — pure noise in a replay fixture, but it
  // does mean a recording is NOT a byte-exact transcript of the live response.
  // The live path deliberately keeps empty-node advisories (a property
  // tests/fetchAdvisories.test.ts asserts), so do not describe replay as
  // "exact".
  advisories: Advisory[];
}

/**
 * Parse a recording file's contents.
 *
 * @throws {Error} naming `path` when the payload is malformed, is a bare
 *   pre-envelope array, or is missing a required field.
 */
export function parseAdvisoryRecording(raw: string, path: string): AdvisoryRecording {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`advisorySource: malformed JSON in advisories file ${path}: ${msg}`);
  }

  // Detect the pre-envelope format explicitly. Without this the field reads
  // below would fail on `undefined.filter` and say nothing useful about why.
  if (Array.isArray(parsed)) {
    throw new Error(
      `advisorySource: ${path} is a bare advisory array (the pre-envelope format). ` +
        'Wrap it as {"recordedAt":…,"sinceISO":…,"ecosystem":…,"advisories":[…]} — ' +
        'preserve the existing array verbatim rather than re-recording, since the ' +
        "live query's rolling 100-advisory window will not return the same set.",
    );
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error(`advisorySource: ${path} is not an advisory recording object`);
  }

  const rec = parsed as Partial<AdvisoryRecording>;
  for (const field of ['recordedAt', 'sinceISO', 'ecosystem'] as const) {
    if (typeof rec[field] !== 'string') {
      throw new Error(
        `advisorySource: ${path} is missing the required "${field}" field`,
      );
    }
  }
  if (!Array.isArray(rec.advisories)) {
    throw new Error(`advisorySource: ${path} is missing the required "advisories" array`);
  }

  return rec as AdvisoryRecording;
}

/**
 * Build an `AdvisoryFetcher` that replays a recording from disk instead of
 * querying GitHub. Deterministic, and needs no GITHUB_TOKEN.
 *
 * The returned fetcher **throws** when the run's ecosystem does not match the
 * recording's. That is the whole point of the envelope: the previous
 * implementation filtered client-side, so a mismatch produced 21 advisories
 * with empty node lists and a confident all-clear.
 *
 * `sinceISO` is not used for filtering — a recording is already a point-in-time
 * snapshot, and its own window is on the envelope. A caller passing `--since`
 * alongside `--advisories-file` gets a warning rather than silent surprise.
 */
export function fileAdvisoryFetcher(path: string): AdvisoryFetcher {
  return async (sinceISO, ecosystem) => {
    let raw: string;
    try {
      raw = await readFile(path, 'utf-8');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`advisorySource: cannot read advisories file ${path}: ${msg}`);
    }

    const recording = parseAdvisoryRecording(raw, path);

    if (recording.ecosystem !== ecosystem) {
      throw new Error(
        `advisorySource: ecosystem mismatch replaying ${path} — the recording was ` +
          `captured for ${recording.ecosystem} but this run requested ${ecosystem}. ` +
          'Replaying it would match nothing and report a false all-clear. Re-record ' +
          `for ${ecosystem}, or run with --ecosystem ${recording.ecosystem}.`,
      );
    }

    if (sinceISO !== recording.sinceISO) {
      // eslint-disable-next-line no-console
      console.warn(
        `[advisorySource] --since is ignored when replaying a recording. ` +
          `${path} covers ${recording.sinceISO} onward (captured ${recording.recordedAt}).`,
      );
    }

    return recording.advisories;
  };
}
