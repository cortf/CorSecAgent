# CorSecAgent

Hybrid cybersecurity automation pipeline that combines deterministic
vulnerability detection (Hunter), deterministic IaC + AWS context assessment
(Cort), deterministic dependency patching (Patcher), and a single-call LLM
report composer (Reporter) into an autonomous GitHub Actions workflow.

See [`CLAUDE.md`](./CLAUDE.md) for the architectural rules and
[`docs/STATUS.md`](./docs/STATUS.md) for what's currently built.

## Deployment

The end-to-end pipeline lives at
[`.github/workflows/corsec-pipeline.yml`](.github/workflows/corsec-pipeline.yml).
It runs on a six-hourly cron (`0 */6 * * *`) and is also manually invocable via
`workflow_dispatch`.

### Required GitHub Actions secrets

| Secret | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Reporter LLM call (Slice 11). Get one from <https://console.anthropic.com/>. |
| `AWS_AUDIT_ROLE_ARN` | The full ARN of the IAM role the workflow assumes via OIDC for Cort's AWS context checks. |
| `GITHUB_TOKEN` | Automatically provided by GitHub Actions; no action required. The PR-creation step uses it to push the patch branch and open the PR. |

### AWS IAM role for OIDC

The workflow obtains short-lived AWS credentials by assuming an IAM role
via GitHub's OIDC provider — no long-lived access keys are stored. Configure
the role's trust policy following the canonical
[GitHub OIDC + AWS guide](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).

The key part of the trust policy is the `StringEquals` condition that scopes
the federated identity to this repository:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:*"
    }
  }
}
```

Replace `OWNER/REPO` with the repository slug. The `StringLike` form allows
the role to be assumed from any branch / tag / PR in the repo; tighten to a
specific `repo:OWNER/REPO:ref:refs/heads/main` form if you want to restrict
to scheduled runs on `main`.

### Required AWS IAM permissions

Read-only — Cort never mutates AWS state. Minimum set:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices"
      ],
      "Resource": "*"
    }
  ]
}
```

If you later add Cort checks against other services (CloudTrail, S3, IAM),
extend this policy with the corresponding `Describe*` / `Get*` / `List*`
actions.

### Dry-run-first deployment

The workflow's `dry_run` input defaults to `true`. In dry-run mode every
artifact is produced and uploaded as a workflow artifact, but **no branch is
pushed and no PR is opened**.

**Run in dry-run for at least a week before flipping to live.** During that
week:

- Inspect the Reporter's `pr-description.md` like a code review. Does it
  surface the right risks? Is the prose clean? Are there sections where it
  invented facts? Each issue is a prompt iteration, not a code change.
- Watch the `[llm-cost]` log line in the orchestrator step. Track total
  per-run tokens against the budget in `docs/STATUS.md`. Template-mode runs
  report `llmTokens: {input: 0, output: 0}`; this is correct, not an
  instrumentation gap (the LLM is intentionally not called when the Reporter
  picks template mode).
- Watch for LLM output-validation failures (missing required headers). They
  show up as a non-zero `finalExitCode` in `.corsec/orchestration-summary.json`.

When dry-run output has been clean and useful for at least a week, switch
`dry_run` to `false` via a manual `workflow_dispatch`. Watch the first real
PR get opened, then merge it after careful human review. After a handful of
real PRs you will have calibration on whether the auto-PRs are trustworthy
enough to auto-merge based on the `automated,security` labels.

### Artifacts produced per run

| File | Producer | Purpose |
| --- | --- | --- |
| `.corsec/hunter-matches.json` | Hunter | `MatchedThreat[]` — every vulnerable dependency the scan found. |
| `.corsec/cort-report.json` | Cort | `AggregatedReport` — IaC findings + AWS context (or empty if no `terraform_dir`). |
| `.corsec/patch-session.json` | Patcher | `PatchSession` — per-package install + test outcomes. |
| `.corsec/pr-description.md` | Reporter | Five-section markdown used as the PR body in live mode. |
| `.corsec/orchestration-summary.json` | Orchestrator | Stage durations, statuses, LLM token totals, branch name, dry-run flag, final exit code. |

All five are uploaded as a single `corsec-artifacts` artifact regardless of
exit code, so dry-run inspection is straightforward.
