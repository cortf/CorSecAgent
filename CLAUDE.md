# CorSecAgent

Hybrid cybersecurity automation pipeline. Two logical modules:

- **Hunter**: deterministic vulnerability detection (GitHub Advisory API + semver matching)
- **Cort**: deterministic IaC + AWS context assessment (Checkov, tfsec, AWS CLI)
- **Reporter**: single LLM call composes PR description from structured inputs

## Stack

- TypeScript (strict), Node 20, tsx for execution
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

All tests live in `tests/` and are named `<module>.test.ts`. The template is
`tests/semverRange.test.ts` — every new test file should follow the same shape.

**Imports:** named imports from vitest (`describe`, `it`, `expect`); source
imported with the `.js` extension (required for NodeNext ESM):

```ts
import { describe, it, expect } from 'vitest';
import { myFn } from '../src/shared/myModule.js';
```

**`describe` block structure:** one block per logical concern, not one block per
function. Group by behaviour category, not by export name:

```
describe('myFn — simple cases', …)
describe('myFn — compound / edge cases', …)
describe('myFn — invalid input (should return false, not throw)', …)
describe('myFn — invalid config (should throw)', …)
describe('Real-world fixture — <source>', …)   // e.g. a GitHub Advisory
```

**`it` strings:** full English sentences stating what should happen, including
the relevant constraint in parentheses when it isn't obvious ("(exclusive upper
bound)", "(semver default)", etc.). No "should" prefix — write in present tense:
`'matches a version below the upper bound'`.

**Fixtures:** real-world data (advisory ranges, lockfile snippets, API payloads)
goes in a `describe` block labelled `'<Source> fixture — <identifier>'`. For
file-based fixtures, load from `fixtures/`. For inline fixtures (short strings),
declare a `const` inside the describe block.

**Error-path tests:** always assert both that the right wrapper type is thrown
(`toThrow(/pattern/)`) and that the error message contains the offending input.

**No `beforeEach` / shared mutable state** unless the setup is genuinely
expensive. Prefer `const` declarations inside each `describe` block.
