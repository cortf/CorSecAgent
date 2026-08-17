// Empty scanner-report builders shared across the suite.
//
// These three shapes were previously defined three times each — once in
// src/orchestrate.ts and once in each of two test files — for nine functions
// covering three shapes, with one name inconsistency between the copies
// (emptyAwsContextReport vs emptyAwsContext).
//
// The src/ copies stay where they are: there they are production values, the
// per-scanner degradation fallbacks the Cort stage substitutes for a scanner
// that failed or never ran. These are the test-only equivalents. tsconfig
// excludes tests/, so a builder that only tests use cannot live in src/ without
// being compiled and shipped — the same problem F17 found with FakeLLMClient.

import type {
  AwsContextReport,
  CheckovReport,
  TfsecReport,
} from '../../src/cort/types.js';

export function emptyCheckovReport(): CheckovReport {
  return { passed: [], failed: [], skipped: [] };
}

export function emptyTfsecReport(): TfsecReport {
  return { passed: [], failed: [] };
}

export function emptyAwsContextReport(): AwsContextReport {
  return { alb: { albArns: [] }, imdsv2: { checked: [] } };
}
