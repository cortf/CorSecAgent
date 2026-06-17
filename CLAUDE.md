# CorSecAgent

Hybrid cybersecurity automation pipeline. Two logical modules:

- **Hunter**: deterministic vulnerability detection (GitHub Advisory API + semver matching)
- **Cort**: deterministic IaC + AWS context assessment (Checkov, tfsec, AWS CLI)
- **Reporter**: single LLM call composes PR description from structured inputs

## Stack

- TypeScript (strict), Node 22, tsx for execution
- GitHub Actions for orchestration (no local runtime)
- Anthropic SDK for the two LLM touchpoints (extraction + report)
- Testing: vitest

## Hard rules

- LLM calls are restricted to: (1) unstructured-text extraction in Hunter,
  (2) final PR description in Reporter. Never anywhere else.
- All version comparison goes through `src/shared/semverRange.ts`.
  Do not call `semver` directly from feature code.
- Read lockfiles, not package.json ranges, for installed versions.
- Checkov/tfsec configs live in `policies/`, not `src/`.

## Current status

See `docs/STATUS.md` for what's built and what's next.

## Conventions

- No `useEffect`-style imperative side effects in module top-level code
- Verbose explanations in code comments for non-obvious logic
- Prefer pure functions; isolate I/O at the edges

## Testing conventions

All tests live in `tests/` and are named `<module>.test.ts`. Two canonical
templates exist — pick the one that fits the module under test:

- Pure functions with no I/O: `tests/semverRange.test.ts`
- Modules with external I/O (network, filesystem): `tests/fetchAdvisories.test.ts`

**Imports:** named imports from vitest (`describe`, `it`, `expect`, `vi` when
mocking); source imported with the `.js` extension (required for NodeNext ESM):

```ts
import { describe, it, expect, vi } from 'vitest';
import { myFn } from '../src/hunter/myModule.js';
```

**`describe` block structure:** one block per logical concern, not one block per
function. Group by behaviour category, not by export name:

```
describe('myFn — simple cases', …)
describe('myFn — compound / edge cases', …)
describe('myFn — invalid input (should return false, not throw)', …)
describe('myFn — invalid config (should throw)', …)
describe('<Source> fixture — <identifier>', …)   // e.g. a GitHub Advisory ID
```

**`it` strings:** full English sentences stating what should happen, including
the relevant constraint in parentheses when it isn't obvious ("(exclusive upper
bound)", "(semver default)", etc.). No "should" prefix — write in present tense:
`'matches a version below the upper bound'`.

**Fixtures:** real-world data (advisory ranges, lockfile snippets, API payloads)
goes in a `describe` block labelled `'<Source> fixture — <identifier>'`. Load
file-based fixtures at module level using the ESM-safe pattern:

```ts
const raw = JSON.parse(
  readFileSync(new URL('../fixtures/my-fixture.json', import.meta.url), 'utf-8'),
) as ExpectedShape;
```

For inline fixtures (short strings), declare a `const` inside the `describe`
block. Never inline large payloads.

**Mocking external clients:** inject the client as an optional last parameter on
the function under test — do not use `vi.mock()` at the module level. Define a
small factory at the top of the test file to reduce repetition:

```ts
function makeClient(response: unknown) {
  return vi.fn().mockResolvedValue(response);
}
```

This keeps auth and network concerns out of tests without coupling the test to
module internals.

**Error-path tests:** always assert both that the right wrapper type is thrown
(`toThrow(/pattern/)`) and that the error message contains the offending input.

**No `beforeEach` / shared mutable state** unless the setup is genuinely
expensive. Prefer `const` declarations inside each `describe` block.

## Completion discipline

Every slice summary must include:

- **What was built** — one or two sentences per file changed
- **Confirmed scope guards** — restate which "do not touch" items the slice
  prompt called out, and confirm they were honoured
- **Any deviations from the spec, with reasoning** — if the implementation
  diverged from the slice prompt (renamed a field, skipped a sub-task, chose a
  different abstraction), name the divergence and explain why
- **Any uncertainty about external system shapes** — API responses, library
  types, runtime behaviour, anything that wasn't fully verified against ground
  truth. Surface this *prominently*, not in a footnote

If the spec turned out to be wrong, say so explicitly. The spec is wrong more
often than the implementation. The slice author operates from general
knowledge and training data; the engineer operates from ground truth (the
actual SDK types, the actual API response shape, the actual lockfile). When
those disagree, ground truth wins — and the gap is the most valuable thing in
the summary, because it's where the architectural model needs updating.

This isn't optional politeness. Two slices in a row, the act of writing a
concrete completion summary surfaced a real architectural assumption that
needed fixing (multi-node advisory traversal in Slice 3; IMDSv2 platform-version
vs task-definition in Slice 8). That's not a coincidence — the summary is
where "what I built" gets compared to "what was specified," and the gap is the
discovery.
