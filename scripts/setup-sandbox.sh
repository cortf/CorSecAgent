#!/usr/bin/env bash
#
# Build (or rebuild) the local test target: a throwaway npm project with
# deliberately vulnerable dependencies and deliberately insecure Terraform.
#
# This exists because the Patcher MUTATES its working directory — it runs
# `git checkout -b` and `npm install` there. Pointing it at CorSecAgent itself
# would create branches and rewrite the lockfile in your real repo. The sandbox
# is a separate git repository so `git checkout -b` cannot escape into the
# parent, and it is disposable so every test run starts from a known state.
#
# Re-run this any time you want a clean slate.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="$REPO_ROOT/sandbox/vulnerable-app"

echo "==> Resetting sandbox at $SANDBOX"
rm -rf "$SANDBOX"
mkdir -p "$SANDBOX/terraform"

# ---------------------------------------------------------------------------
# Vulnerable dependency set.
#
# Versions are pinned EXACTLY (no ^ or ~). A caret range would let npm resolve
# to the already-patched latest release and the scan would find nothing.
#
#   crypto-js  3.3.0   -> GHSA-rg76-677x-56q9 (CRITICAL), fixed in 4.0.0
#   hono       4.12.0  -> three separate advisories, all fixed in 4.12.34.
#                         Exercises the Patcher's consolidation path: three
#                         GHSAs must collapse into ONE npm install at the
#                         highest patched version.
#   dompurify  3.4.12  -> GHSA-55q2-fjhq-7xh7 (MODERATE), fixed in 3.4.13
# ---------------------------------------------------------------------------
cat > "$SANDBOX/package.json" <<'JSON'
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "description": "Deliberately vulnerable test target for CorSecAgent",
  "private": true,
  "scripts": {
    "test": "node -e \"const fs=require('fs');for(const p of ['crypto-js','dompurify','hono'])fs.accessSync('node_modules/'+p+'/package.json');console.log('smoke test ok')\""
  },
  "dependencies": {
    "crypto-js": "3.3.0",
    "dompurify": "3.4.12",
    "hono": "4.12.0"
  }
}
JSON

cat > "$SANDBOX/.gitignore" <<'GITIGNORE'
node_modules/
GITIGNORE

# ---------------------------------------------------------------------------
# Insecure Terraform.
#
# The violations are chosen so Checkov and tfsec BOTH flag the same underlying
# problems (unencrypted S3, world-open security group, missing IMDSv2). That
# overlap is deliberate: it gives the Cort aggregator real cross-scanner
# material to deduplicate, rather than two disjoint finding lists.
# ---------------------------------------------------------------------------
cat > "$SANDBOX/terraform/s3.tf" <<'TF'
resource "aws_s3_bucket" "data" {
  bucket = "corsec-test-data-bucket"
}

# No server-side encryption, no versioning, no access logging, and a public ACL.
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
TF

cat > "$SANDBOX/terraform/network.tf" <<'TF'
resource "aws_security_group" "wide_open" {
  name        = "corsec-test-wide-open"
  description = "Intentionally insecure security group for pipeline testing"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
TF

cat > "$SANDBOX/terraform/compute.tf" <<'TF'
resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # metadata_options omitted entirely -> IMDSv1 permitted (no http_tokens = "required").
  # Unencrypted root volume.
  root_block_device {
    encrypted = false
  }

  vpc_security_group_ids = [aws_security_group.wide_open.id]
}
TF

# ---------------------------------------------------------------------------
# Install and commit.
# ---------------------------------------------------------------------------
echo "==> Installing vulnerable dependencies (this generates the lockfile Hunter reads)"
cd "$SANDBOX"
npm install --silent --no-audit --no-fund

echo "==> Initialising an isolated git repository"
git init --quiet --initial-branch=main
# Set identity locally so the commit works even on machines with no global
# git config, and so this never touches the user's global settings.
git config user.email "corsec-sandbox@example.invalid"
git config user.name "CorSec Sandbox"
git add -A
git commit --quiet -m "Initial vulnerable state"

echo ""
echo "==> Sandbox ready: $SANDBOX"
echo "    Installed versions:"
node -e "
const l=require('./package-lock.json');
for (const p of ['crypto-js','dompurify','hono']) {
  console.log('      ' + p.padEnd(12) + l.packages['node_modules/'+p].version);
}
"
