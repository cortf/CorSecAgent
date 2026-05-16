# GitHub Advisory API fixture

Recorded: `publishedSince: "2024-01-03T21:00:00Z"`, `first: 10`, ecosystem filter `NPM` (applied in the `vulnerabilities` sub-query, not at the top level).

## Shape properties this fixture exercises

- `securityAdvisories.nodes` is a list of advisories
- Each advisory's `vulnerabilities.nodes` is itself a list — a single
  advisory can describe multiple vulnerable version ranges for the
  same or different packages
- `GHSA-f8mp-x433-5wpf` demonstrates the multi-node case: two nodes
  for `wrangler`, covering `>= 2.0.0, < 2.20.2` AND `>= 3.0.0, < 3.19.0`
- Most advisories on the page have zero NPM vulnerabilities; the
  ecosystem filter happens server-side but consumers must not
  assume every returned advisory has matching `vulnerabilities.nodes`

## What to watch for when re-recording

If the API shape changes, tests that load this fixture will break in
a way that points directly at the mismatch — that is the point.
Re-record by running:

```
gh api graphql -f query='...' > fixtures/github-advisory-api.json
```

using the same query in `src/hunter/fetchAdvisories.ts` and updating
this file with the new snapshot date.
