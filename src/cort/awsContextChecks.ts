import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  type DescribeLoadBalancersCommandOutput,
  type LoadBalancer,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import {
  ECSClient,
  ListClustersCommand,
  type ListClustersCommandOutput,
  ListServicesCommand,
  type ListServicesCommandOutput,
  DescribeServicesCommand,
  type DescribeServicesCommandOutput,
  type Service,
} from '@aws-sdk/client-ecs';
import { isAtLeast } from '../shared/semverRange.js';
import type {
  AlbContextFinding,
  AwsContextReport,
  Imdsv2Finding,
  Imdsv2Report,
} from './types.js';

// Re-export the AWS SDK client classes so tests can construct fake clients with
// the same nominal types the production code expects. Keeping the public surface
// of this module narrow: callers either let us build the default clients (which
// rely on the AWS SDK's default credential chain — fed by OIDC in CI) or inject
// pre-configured client instances (which is also how tests inject mocks).
export type AlbClient = ElasticLoadBalancingV2Client;
export type EcsClient = ECSClient;

// ─────────────────────────────────────────────────────────────────────────────
// ALB presence check
// ─────────────────────────────────────────────────────────────────────────────

// Filters to Type === 'application' so NLBs and GWLBs are excluded — the
// question we are answering is specifically "is there an ALB in front of
// anything in this account", since ALBs are where WAF / path-based routing /
// header inspection can sit. A future slice may refine this to "is THIS
// service behind an ALB" by joining against target groups.
//
// Pagination: the ELBv2 API uses `Marker` / `NextMarker` (not `NextToken`).
// We loop until `NextMarker` is absent, accumulating ALBs across pages.
export async function checkAlbPresence(
  client: AlbClient = new ElasticLoadBalancingV2Client({}),
): Promise<AlbContextFinding> {
  const albArns: string[] = [];
  let marker: string | undefined = undefined;

  try {
    do {
      const out: DescribeLoadBalancersCommandOutput = await client.send(
        new DescribeLoadBalancersCommand({ Marker: marker }),
      );

      const page: LoadBalancer[] = out.LoadBalancers ?? [];
      for (const lb of page) {
        if (lb.Type === 'application' && lb.LoadBalancerArn) {
          albArns.push(lb.LoadBalancerArn);
        }
      }

      marker = out.NextMarker;
    } while (marker);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`checkAlbPresence: ALB DescribeLoadBalancers call failed: ${msg}`);
  }

  return {
    albCount: albArns.length,
    albArns,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Fargate IMDSv2 enforcement check
//
// Approach: this check asks "are the services that run our Fargate tasks on a
// Fargate platform version that enforces IMDSv2?" — *not* "is the task
// definition configured for IMDSv2?". The latter is unanswerable from the AWS
// SDK: TaskDefinition has no HttpTokens field. IMDSv2 enforcement on Fargate
// is controlled by the Fargate platform version (1.4.0+ enforces IMDSv2 with
// a hop limit of 2 by default; `LATEST` is always the current platform).
//
// Pipeline:
//   1. ListClusters → cluster ARNs (paginated via nextToken)
//   2. For each cluster: ListServices(cluster) → service ARNs (paginated)
//   3. For each cluster: DescribeServices in batches of ≤ 10 service ARNs
//      (DescribeServices's documented per-call max is 10) → Service[]
//   4. Filter to Fargate services (launchType=FARGATE OR capacity provider
//      strategy contains FARGATE / FARGATE_SPOT). EC2 / EXTERNAL services are
//      skipped — the slice scope is Fargate.
//   5. Classify each Fargate service's platformVersion via
//      classifyPlatformVersion and emit one Imdsv2Finding per service.
//
// References:
//   - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html
//   - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-task-networking.html
//   - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeServices.html
// ─────────────────────────────────────────────────────────────────────────────

// AWS-documented per-call cap on DescribeServices. Used to chunk service ARNs.
const DESCRIBE_SERVICES_BATCH_SIZE = 10;

export async function checkFargateImdsv2(
  client: EcsClient = new ECSClient({}),
): Promise<Imdsv2Report> {
  // Step 1: list every cluster ARN, walking nextToken.
  const clusterArns = await listAllClusterArns(client);

  // Step 2 + 3: per cluster, list service ARNs (paginated) and then describe
  // them in batches of ≤ 10. The describe call is cluster-scoped, so this is a
  // natural per-cluster fanout rather than one flat list of services.
  const findings: Imdsv2Finding[] = [];
  for (const clusterArn of clusterArns) {
    const serviceArns = await listAllServiceArns(client, clusterArn);
    if (serviceArns.length === 0) continue;

    const services = await describeServicesInBatches(client, clusterArn, serviceArns);
    for (const svc of services) {
      if (!isFargateService(svc)) continue;
      findings.push(toFinding(svc, clusterArn));
    }
  }

  const compliantCount = findings.filter((f) => f.compliant).length;
  const nonCompliantCount = findings.length - compliantCount;

  return {
    checked: findings,
    compliantCount,
    nonCompliantCount,
  };
}

async function listAllClusterArns(client: EcsClient): Promise<string[]> {
  const arns: string[] = [];
  let nextToken: string | undefined = undefined;
  try {
    do {
      const out: ListClustersCommandOutput = await client.send(
        new ListClustersCommand({ nextToken }),
      );
      for (const arn of out.clusterArns ?? []) arns.push(arn);
      nextToken = out.nextToken;
    } while (nextToken);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`checkFargateImdsv2: Fargate ListClusters call failed: ${msg}`);
  }
  return arns;
}

async function listAllServiceArns(client: EcsClient, clusterArn: string): Promise<string[]> {
  const arns: string[] = [];
  let nextToken: string | undefined = undefined;
  try {
    do {
      const out: ListServicesCommandOutput = await client.send(
        new ListServicesCommand({ cluster: clusterArn, nextToken }),
      );
      for (const arn of out.serviceArns ?? []) arns.push(arn);
      nextToken = out.nextToken;
    } while (nextToken);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `checkFargateImdsv2: Fargate ListServices call failed for cluster ${clusterArn}: ${msg}`,
    );
  }
  return arns;
}

async function describeServicesInBatches(
  client: EcsClient,
  clusterArn: string,
  serviceArns: string[],
): Promise<Service[]> {
  const services: Service[] = [];
  for (let i = 0; i < serviceArns.length; i += DESCRIBE_SERVICES_BATCH_SIZE) {
    const batch = serviceArns.slice(i, i + DESCRIBE_SERVICES_BATCH_SIZE);
    try {
      const out: DescribeServicesCommandOutput = await client.send(
        new DescribeServicesCommand({ cluster: clusterArn, services: batch }),
      );
      for (const s of out.services ?? []) services.push(s);
      // out.failures is intentionally ignored here: a partial failure on one
      // service (e.g. it was deleted mid-call) should not poison the whole
      // check. The successful services in the same response are still useful
      // and will be classified normally.
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `checkFargateImdsv2: Fargate DescribeServices call failed for cluster ${clusterArn}: ${msg}`,
      );
    }
  }
  return services;
}

// A service is "Fargate" if either its explicit launchType is FARGATE, or any
// capacity provider in its strategy is one of the Fargate capacity providers.
// Per the SDK docs the two fields are mutually exclusive on a given service
// (launchType is omitted from DescribeServices output when a capacity provider
// strategy was used), so checking both covers every Fargate-running shape.
function isFargateService(s: Service): boolean {
  if (s.launchType === 'FARGATE') return true;
  const providers = (s.capacityProviderStrategy ?? []).map((p) => p.capacityProvider);
  return providers.includes('FARGATE') || providers.includes('FARGATE_SPOT');
}

function toFinding(s: Service, clusterArn: string): Imdsv2Finding {
  const { platformVersion, compliant } = classifyPlatformVersion(s.platformVersion);
  return {
    serviceArn: s.serviceArn ?? '',
    serviceName: s.serviceName ?? '',
    // s.clusterArn is set by AWS, but fall back to the cluster we are iterating
    // so the finding always has a real value (defensive against future SDK
    // shape drift; in practice the two are equal).
    clusterArn: s.clusterArn ?? clusterArn,
    taskDefinitionArn: s.taskDefinition ?? '',
    platformVersion,
    compliant,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Composite orchestrator
//
// Runs both checks and rolls them into a single AwsContextReport so downstream
// consumers (Slice 9 aggregator) depend on one top-level shape rather than two.
// ─────────────────────────────────────────────────────────────────────────────
export async function runAwsContextChecks(
  elbClient?: AlbClient,
  ecsClient?: EcsClient,
): Promise<AwsContextReport> {
  // Deliberately sequential rather than Promise.all — the two checks hit
  // different AWS services so error attribution stays clean (we don't want a
  // Fargate failure to surface as "AWS context checks failed"; the per-check
  // wrappers already name which call failed).
  const alb = await checkAlbPresence(elbClient);
  const imdsv2 = await checkFargateImdsv2(ecsClient);
  return { alb, imdsv2 };
}

// Encodes the IMDSv2-via-platform-version rule in isolation so it is unit-
// testable independently of the SDK plumbing.
//
//   undefined / null / ''   → 'LATEST', compliant — AWS docs: an absent
//                              platformVersion on a Fargate service defaults
//                              to LATEST at run time
//   'LATEST'                → 'LATEST', compliant — always the current
//                              platform; Fargate has shipped IMDSv2-by-default
//                              since 1.4.0 (April 2020)
//   '1.4.0' or any version  → compliant iff the version is at least 1.4.0,
//                              per the shared semverRange helper (no direct
//                              `semver` calls per CLAUDE.md hard rules)
//   Invalid semver string   → reported verbatim as the platformVersion, but
//                              non-compliant — we surface the bad data rather
//                              than silently asserting safety
export function classifyPlatformVersion(
  raw: string | undefined | null,
): { platformVersion: string; compliant: boolean } {
  if (!raw || raw === 'LATEST') {
    return { platformVersion: 'LATEST', compliant: true };
  }
  // isAtLeast returns false for an unparseable version rather than throwing, so
  // the defensive try/catch this used to need is gone. A malformed
  // platformVersion is reported non-compliant, which is what the catch did.
  return { platformVersion: raw, compliant: isAtLeast(raw, '1.4.0') };
}
