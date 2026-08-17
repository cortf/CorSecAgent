// Reporter — the single LLM touchpoint that runs on every confirmed
// vulnerability cycle. Cost discipline matters here more than anywhere
// else in the pipeline, hence three design choices worth re-reading
// before changing this module:
//
//   1. Structured input, prose output. The Reporter consumes pre-digested
//      JSON (Hunter matches + Cort aggregated report + Patcher session)
//      and produces markdown formatted to a fixed five-section schema.
//      The LLM never sees raw scanner output, raw advisory bodies, or
//      raw test logs.
//   2. Template-only fallback. When the session is trivially "clean
//      patches, no Cort findings, no context concerns", the prose call
//      is skipped entirely and a deterministic markdown template is
//      rendered. This is checked BEFORE the prompt is assembled.
//   3. Single call, no retries. Failures bubble up — Slice 12's
//      orchestrator decides whether to retry the whole job.

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { MatchedThreat } from '../hunter/types.js';
import type { AggregatedReport } from '../cort/types.js';
import { imdsv2Counts } from '../cort/types.js';
import type { PatchSession } from '../patcher/types.js';
import type { LLMClient } from '../shared/llmClient.js';
import { AnthropicLLMClient } from '../shared/llmClient.js';

// Model string for the Reporter's single LLM call.
//
// Substitution note: the Slice 11 spec used `claude-sonnet-4-7-20250228`
// as a placeholder. No Sonnet 4.7 model exists in the current model
// catalogue; the latest Sonnet at the time of writing is
// `claude-sonnet-4-6`, which is what we route through. If the catalogue
// advances, swap this constant — it is the only place the model name
// lives.
const REPORTER_MODEL = 'claude-sonnet-4-6';

// Hard upper bound on the serialized user-message payload. Documented in
// the slice prompt: under ~1500 input tokens, ~6000 characters at 4
// chars/token. We assert in code rather than hoping the model behaves.
const USER_MESSAGE_MAX_CHARS = 6000;

// Max output tokens — Slice 11 budget targets <600 output tokens at
// well under $0.01 per call.
const REPORTER_MAX_TOKENS = 800;

// Path to the version-controlled system prompt template. Read lazily on
// first call so unit tests of this module don't touch the filesystem
// unless the LLM-mode branch is actually exercised.
const PROMPT_TEMPLATE_PATH = fileURLToPath(
  new URL('./prompts/pr-description.md', import.meta.url),
);

// Five required section headers, in required order. Both the template
// renderer and the LLM-output validator use this list.
const REQUIRED_SECTIONS = [
  '## Risk Summary',
  '## Affected Dependencies',
  '## Patches Applied',
  '## Infrastructure Hardening',
  '## Test Results',
] as const;

export interface ComposePROptions {
  matchesPath: string;
  cortReportPath: string;
  patchSessionPath: string;
  outputPath: string;
}

type ReporterMode = 'template' | 'llm';

// Trimmed shapes that go into the user-message JSON. These intentionally
// strip large/noisy fields (vulnerableRange, errorMessage, guideline, etc.)
// — the model doesn't need them and they would blow the token budget. The
// session's captured test output (PatchSession.testRun) is likewise never a
// payload key: it is the single largest field in the session, capped at 5KB,
// and the model reasons from each result's status instead.
interface TrimmedVulnerability {
  ghsaId: string;
  packageName: string;
  severity: string;
  cvssScore: number | null;
  summary: string;
}

interface TrimmedInfraFinding {
  category: string;
  severity: string;
  resource: string;
  description: string;
  sources: Array<{ scanner: string; ruleId: string }>;
}

interface TrimmedInfrastructure {
  findings: TrimmedInfraFinding[];
  context: {
    alb: { albCount: number };
    imdsv2: { compliantCount: number; nonCompliantCount: number };
  };
}

interface TrimmedPatch {
  packageName: string;
  previousVersion: string;
  installedVersion: string | null;
  status: string;
  relatedMatches: string[];
}

interface ReporterPayload {
  vulnerabilities: TrimmedVulnerability[];
  infrastructure: TrimmedInfrastructure;
  patches: TrimmedPatch[];
}

/**
 * Compose a PR description from three structured inputs:
 *   - Hunter's matches.json (MatchedThreat[])
 *   - Cort's aggregated report (AggregatedReport)
 *   - Patcher's session (PatchSession)
 *
 * Decides up front whether the case is trivial enough to render via the
 * deterministic template (no LLM call) or whether it warrants prose
 * synthesis (single LLM call). Writes the final markdown to outputPath
 * and returns it.
 *
 * `llmClient` is injectable so tests can drive the LLM branch via the
 * FakeLLMClient without an API key. Default is `AnthropicLLMClient`,
 * which is constructed lazily — only when the LLM branch is taken.
 */
export async function composePR(
  opts: ComposePROptions,
  llmClient?: LLMClient,
): Promise<string> {
  const [matches, cortReport, patchSession] = await Promise.all([
    readJson<MatchedThreat[]>(opts.matchesPath),
    readJson<AggregatedReport>(opts.cortReportPath),
    readJson<PatchSession>(opts.patchSessionPath),
  ]);

  const mode = decideMode(cortReport, patchSession);
  // Observability: Slice 12's workflow can grep this line to track how
  // often the reporter actually invokes the LLM vs. uses the template.
  // eslint-disable-next-line no-console
  console.log(`[reporter] mode=${mode}`);

  let markdown: string;
  if (mode === 'template') {
    markdown = renderTemplate(patchSession);
  } else {
    const client = llmClient ?? new AnthropicLLMClient();
    markdown = await composeViaLLM(client, matches, cortReport, patchSession);
  }

  validateSections(markdown);
  await writeFile(opts.outputPath, markdown, 'utf-8');
  return markdown;
}

// Template-only mode triggers when ALL of these are true:
//   - every patch result is `patched-tests-passed`
//   - Cort's findings array is empty
//   - Cort's context shows no concerns: imdsv2 has zero non-compliant
//     services (compliant or empty is fine), and ALB count is not zero
//     (we treat presence-of-ALB as the affirmative signal).
//
// The ALB-count rule encodes a subtle Slice 8/9 design choice — ALB
// presence is a positive risk-modifying signal (defense in depth via
// WAF / SSL termination / centralised auth). Zero ALBs in an account
// that runs Fargate services means the model has something worth
// narrating; with zero services it's a wash, so the template still wins
// in that degenerate empty-account case.
function decideMode(
  cortReport: AggregatedReport,
  patchSession: PatchSession,
): ReporterMode {
  if (cortReport.findings.length > 0) return 'llm';
  if (imdsv2Counts(cortReport.context.imdsv2).nonCompliant > 0) return 'llm';

  // ALB context is only meaningful when there's deployed compute. If the
  // account has any Fargate services AND zero ALBs, that is a missing
  // hardening signal worth narrating. Empty accounts (no services AND
  // no ALBs) stay in template mode.
  //
  // "Any Fargate services" is `checked.length > 0` directly. It used to be
  // reconstructed as compliantCount + nonCompliantCount > 0 — the same
  // question asked the long way round, via two stored fields that could (and
  // in every committed fixture did) disagree with `checked`.
  const hasFargateServices = cortReport.context.imdsv2.checked.length > 0;
  if (hasFargateServices && cortReport.context.alb.albArns.length === 0) {
    return 'llm';
  }

  for (const result of patchSession.results) {
    if (result.status !== 'patched-tests-passed') return 'llm';
  }

  return 'template';
}

// Build the structured user-message payload, run the single LLM call,
// return the model's output text. Asserts payload size; does NOT retry.
async function composeViaLLM(
  client: LLMClient,
  matches: MatchedThreat[],
  cortReport: AggregatedReport,
  patchSession: PatchSession,
): Promise<string> {
  const imdsv2 = imdsv2Counts(cortReport.context.imdsv2);
  const payload: ReporterPayload = {
    vulnerabilities: matches.map((m) => ({
      ghsaId: m.ghsaId,
      packageName: m.packageName,
      severity: m.severity,
      cvssScore: m.cvssScore,
      summary: m.summary,
    })),
    infrastructure: {
      findings: cortReport.findings.map((f) => ({
        category: f.category,
        severity: f.severity,
        resource: f.resource,
        description: f.description,
        sources: f.sources.map((s) => ({ scanner: s.scanner, ruleId: s.ruleId })),
      })),
      // The model-facing contract still speaks in counts — prompts/pr-description.md
      // documents albCount / compliantCount / nonCompliantCount by name — so
      // they are derived here, at the boundary, rather than stored upstream.
      context: {
        alb: { albCount: cortReport.context.alb.albArns.length },
        imdsv2: {
          compliantCount: imdsv2.compliant,
          nonCompliantCount: imdsv2.nonCompliant,
        },
      },
    },
    patches: patchSession.results.map((r) => ({
      packageName: r.packageName,
      previousVersion: r.previousVersion,
      installedVersion: r.installedVersion,
      status: r.status,
      relatedMatches: r.relatedMatches,
    })),
  };

  const userMessage = JSON.stringify(payload);
  if (userMessage.length > USER_MESSAGE_MAX_CHARS) {
    throw new Error(
      `composePR: serialized payload is ${userMessage.length} chars, ` +
        `over the ${USER_MESSAGE_MAX_CHARS}-char budget. Reduce inputs before retrying.`,
    );
  }

  const systemPrompt = await readPromptTemplate();
  const result = await client.complete({
    model: REPORTER_MODEL,
    systemPrompt,
    userMessage,
    maxTokens: REPORTER_MAX_TOKENS,
  });
  return result.text;
}

// The document rendered when a template-mode session has no results at all.
//
// Reached only via the vacuous case: decideMode returns 'template' when EVERY
// result is 'patched-tests-passed', which an empty array satisfies trivially —
// and an empty session is exactly what orchestrate.ts manufactures when the
// Patcher throws. Held as a constant so the condition is evaluated once, at the
// top, instead of being re-tested inside each of the five sections.
//
// No trailing newline, and a blank line between every header and its body: the
// exact bytes matter because a dropped blank line breaks markdown list
// rendering in a PR body.
const EMPTY_SESSION_TEMPLATE = [
  '## Risk Summary',
  'None.',
  '',
  '## Affected Dependencies',
  'None.',
  '',
  '## Patches Applied',
  'None.',
  '',
  '## Infrastructure Hardening',
  'None.',
  '',
  '## Test Results',
  'No tests run (no patches applied).',
].join('\n');

// Deterministic markdown for the trivial case: every patch landed, every
// test passed, no Cort findings to narrate. The five required headers
// always appear in order so the validator passes uniformly.
//
// Renders `session.results` directly. It used to filter to
// status === 'patched-tests-passed' first, but decideMode returns 'template'
// only when every result already has that status — so the filter was always
// identical in content to session.results and could never remove an element.
// That no-op was then branched on four times, each testing the same condition,
// which reduces to `results.length === 0`.
//
// The filter also read as defensive while being a data-loss channel: widen
// decideMode to admit another status (skipped-already-resolved, say, as a
// plausible cost optimisation) and it would silently drop those rows —
// undercounting GHSAs in the Risk Summary and omitting advisories from Affected
// Dependencies, in a security document, with no test failing.
function renderTemplate(session: PatchSession): string {
  const applied = session.results;
  if (applied.length === 0) return EMPTY_SESSION_TEMPLATE;

  const packages = applied.length;
  const ghsas = applied.reduce((sum, r) => sum + r.relatedMatches.length, 0);

  const lines: string[] = [];

  lines.push('## Risk Summary');
  lines.push(
    `Applied ${ghsas} security patch${ghsas === 1 ? '' : 'es'} across ${packages} package${packages === 1 ? '' : 's'}. All tests passing.`,
  );
  lines.push('');

  lines.push('## Affected Dependencies');
  for (const r of applied) {
    lines.push(`- ${r.packageName}: ${r.relatedMatches.join(', ')}`);
  }
  lines.push('');

  lines.push('## Patches Applied');
  for (const r of applied) {
    const installed = r.installedVersion ?? r.previousVersion;
    lines.push(`- ${r.packageName}: ${r.previousVersion} → ${installed} (${r.status})`);
  }
  lines.push('');

  lines.push('## Infrastructure Hardening');
  lines.push('None.');
  lines.push('');

  lines.push('## Test Results');
  lines.push('All tests passing after patch installation.');

  return lines.join('\n');
}

// Validate that the five required section headers all appear in the
// required order. Throws on any deviation so the orchestrator can
// observe the failure — it does NOT attempt to repair the output.
function validateSections(markdown: string): void {
  let cursor = 0;
  for (const header of REQUIRED_SECTIONS) {
    const found = markdown.indexOf(header, cursor);
    if (found === -1) {
      throw new Error(
        `composePR: output is missing required section header "${header}" ` +
          `(or it appears out of order). Required order: ${REQUIRED_SECTIONS.join(
            ', ',
          )}.`,
      );
    }
    cursor = found + header.length;
  }
}

// Read + parse helper. Wraps the underlying error with the offending
// path so the workflow log points at the right input file when something
// is malformed.
async function readJson<T>(path: string): Promise<T> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`composePR: failed to read ${path}: ${msg}`);
  }
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`composePR: failed to parse JSON at ${path}: ${msg}`);
  }
}

async function readPromptTemplate(): Promise<string> {
  try {
    return await readFile(PROMPT_TEMPLATE_PATH, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `composePR: failed to read prompt template at ${PROMPT_TEMPLATE_PATH}: ${msg}`,
    );
  }
}

// Exported for tests — lets test code verify the consolidation decision
// without recomposing a full Reporter run.
export const __testing = {
  decideMode,
  renderTemplate,
  validateSections,
  USER_MESSAGE_MAX_CHARS,
  REQUIRED_SECTIONS,
  REPORTER_MODEL,
};
