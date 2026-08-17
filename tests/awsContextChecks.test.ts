import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  DescribeLoadBalancersCommand,
  type DescribeLoadBalancersCommandOutput,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import {
  ListClustersCommand,
  type ListClustersCommandOutput,
  ListServicesCommand,
  type ListServicesCommandOutput,
  DescribeServicesCommand,
  type DescribeServicesCommandOutput,
} from '@aws-sdk/client-ecs';
import {
  checkAlbPresence,
  checkFargateImdsv2,
  classifyPlatformVersion,
  runAwsContextChecks,
  type AlbClient,
  type EcsClient,
} from '../src/cort/awsContextChecks.js';
import { imdsv2Counts } from '../src/cort/types.js';

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
//
// All fixtures live in fixtures/aws/ and are loaded once at module level so the
// tests stay focused on assertions, not file plumbing. Shapes mirror what the
// real SDK returns; the wrapper happens to ignore most fields.
// ─────────────────────────────────────────────────────────────────────────────
const lbMixedResponse = JSON.parse(
  readFileSync(new URL('../fixtures/aws/describe-load-balancers-mixed.json', import.meta.url), 'utf-8'),
) as DescribeLoadBalancersCommandOutput;

const lbEmptyResponse = JSON.parse(
  readFileSync(new URL('../fixtures/aws/describe-load-balancers-empty.json', import.meta.url), 'utf-8'),
) as DescribeLoadBalancersCommandOutput;

// describe-services-mixed.json: 5 services on a single "prod" cluster —
//   web-frontend  : launchType FARGATE, platformVersion LATEST  → compliant
//   api-server    : launchType FARGATE, platformVersion 1.4.0   → compliant
//   legacy-worker : launchType FARGATE, platformVersion 1.3.0   → non-compliant
//   spot-batch    : capacityProviderStrategy FARGATE_SPOT, no platformVersion
//                                                              → LATEST/compliant
//   ec2-batch-... : launchType EC2                              → skipped
// (so total Fargate findings = 4, compliant = 3, non-compliant = 1)
const describeServicesMixed = JSON.parse(
  readFileSync(new URL('../fixtures/aws/describe-services-mixed.json', import.meta.url), 'utf-8'),
) as DescribeServicesCommandOutput;

const PROD_CLUSTER_ARN = 'arn:aws:ecs:us-east-1:111122223333:cluster/prod';

// ─────────────────────────────────────────────────────────────────────────────
// Mock client factory
//
// AWS SDK v3 clients expose all behaviour through `send(command)`. We construct
// a minimal fake by stubbing `send` with vi.fn() and dispatching on the
// command's constructor name so the same client can answer multiple command
// types within one test. The `as unknown as T` cast is the canonical SDK v3
// mocking pattern — we deliberately narrow a partial implementation to the
// full client interface for test purposes.
// ─────────────────────────────────────────────────────────────────────────────
type CommandHandler = (cmd: unknown) => unknown | Promise<unknown>;

function makeClient<T>(handler: CommandHandler): T {
  const send = vi.fn(async (cmd: unknown) => handler(cmd));
  return { send } as unknown as T;
}

// ─────────────────────────────────────────────────────────────────────────────
// checkAlbPresence
// ─────────────────────────────────────────────────────────────────────────────

describe('checkAlbPresence — filtering by Type === "application"', () => {
  it('returns only the two ALBs and excludes the network load balancer from the mixed fixture', async () => {
    const client = makeClient<AlbClient>((cmd) => {
      if (cmd instanceof DescribeLoadBalancersCommand) return lbMixedResponse;
      throw new Error('unexpected command');
    });

    const finding = await checkAlbPresence(client);

    expect(finding.albArns).toHaveLength(2);
    expect(finding.albArns).toHaveLength(2);
    expect(finding.albArns.every((arn) => arn.includes(':loadbalancer/app/'))).toBe(true);
    expect(finding.albArns.some((arn) => arn.includes(':loadbalancer/net/'))).toBe(false);
  });
});

describe('checkAlbPresence — empty account', () => {
  it('returns an empty arn array when DescribeLoadBalancers returns no load balancers', async () => {
    const client = makeClient<AlbClient>((cmd) => {
      if (cmd instanceof DescribeLoadBalancersCommand) return lbEmptyResponse;
      throw new Error('unexpected command');
    });

    const finding = await checkAlbPresence(client);

    expect(finding.albArns).toEqual([]);
  });
});

describe('checkAlbPresence — pagination', () => {
  it('walks Marker/NextMarker across two pages and accumulates ALBs from both', async () => {
    const page1: DescribeLoadBalancersCommandOutput = {
      $metadata: {},
      LoadBalancers: [
        {
          LoadBalancerArn: 'arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/page1-alb/p1',
          Type: 'application',
        },
      ],
      NextMarker: 'cursor-1',
    };
    const page2: DescribeLoadBalancersCommandOutput = {
      $metadata: {},
      LoadBalancers: [
        {
          LoadBalancerArn: 'arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/page2-alb/p2',
          Type: 'application',
        },
      ],
    };

    const send = vi.fn(async (cmd: unknown) => {
      if (cmd instanceof DescribeLoadBalancersCommand) {
        const input = cmd.input as { Marker?: string };
        return input.Marker === 'cursor-1' ? page2 : page1;
      }
      throw new Error('unexpected command');
    });
    const client = { send } as unknown as AlbClient;

    const finding = await checkAlbPresence(client);

    expect(send).toHaveBeenCalledTimes(2);
    expect(finding.albArns).toHaveLength(2);
    expect(finding.albArns).toEqual([
      'arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/page1-alb/p1',
      'arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/page2-alb/p2',
    ]);
  });
});

describe('checkAlbPresence — error wrapping', () => {
  it('throws an error naming the ALB check when the underlying SDK call rejects', async () => {
    const client = makeClient<AlbClient>(() => {
      throw new Error('AccessDenied: not authorized to call DescribeLoadBalancers');
    });

    await expect(checkAlbPresence(client)).rejects.toThrow(/checkAlbPresence/);
    await expect(checkAlbPresence(client)).rejects.toThrow(/ALB/);
    await expect(checkAlbPresence(client)).rejects.toThrow(/AccessDenied/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// classifyPlatformVersion
//
// The compliance rule is extracted into its own function so it can be tested
// independently of the SDK plumbing. Fargate has shipped IMDSv2-by-default
// since platform version 1.4.0 (April 2020); 'LATEST' is always the current
// platform, so an absent or 'LATEST' platformVersion is compliant.
// ─────────────────────────────────────────────────────────────────────────────

describe('classifyPlatformVersion — LATEST and absent', () => {
  it('treats undefined as LATEST and compliant (AWS docs: absent platformVersion on a Fargate service defaults to LATEST)', () => {
    expect(classifyPlatformVersion(undefined)).toEqual({ platformVersion: 'LATEST', compliant: true });
  });

  it('treats null as LATEST and compliant', () => {
    expect(classifyPlatformVersion(null)).toEqual({ platformVersion: 'LATEST', compliant: true });
  });

  it('treats empty string as LATEST and compliant', () => {
    expect(classifyPlatformVersion('')).toEqual({ platformVersion: 'LATEST', compliant: true });
  });

  it('treats the literal "LATEST" as compliant', () => {
    expect(classifyPlatformVersion('LATEST')).toEqual({ platformVersion: 'LATEST', compliant: true });
  });
});

describe('classifyPlatformVersion — specific version comparison (boundary at >= 1.4.0)', () => {
  it('flags "1.4.0" as compliant (boundary — IMDSv2-by-default arrived in 1.4.0)', () => {
    expect(classifyPlatformVersion('1.4.0')).toEqual({ platformVersion: '1.4.0', compliant: true });
  });

  it('flags "1.5.0" as compliant (above the boundary)', () => {
    expect(classifyPlatformVersion('1.5.0')).toEqual({ platformVersion: '1.5.0', compliant: true });
  });

  it('flags "1.3.0" as non-compliant (one minor below the boundary)', () => {
    expect(classifyPlatformVersion('1.3.0')).toEqual({ platformVersion: '1.3.0', compliant: false });
  });

  it('flags "1.0.0" as non-compliant', () => {
    expect(classifyPlatformVersion('1.0.0')).toEqual({ platformVersion: '1.0.0', compliant: false });
  });
});

describe('classifyPlatformVersion — invalid input (should not throw)', () => {
  it('returns the raw value verbatim and non-compliant for a malformed version string (surface the bad data; do not assert safety)', () => {
    expect(classifyPlatformVersion('not-a-version')).toEqual({
      platformVersion: 'not-a-version',
      compliant: false,
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// checkFargateImdsv2
//
// Tests the full pipeline: ListClusters → ListServices(per cluster) →
// DescribeServices (in batches of ≤ 10) → Fargate filter → classification.
// ─────────────────────────────────────────────────────────────────────────────

// Common dispatcher for an ECS client that talks about a single cluster. Tests
// using more than one cluster build their own dispatcher inline.
function makeSingleClusterEcsClient(
  clusterArn: string,
  serviceArns: string[],
  describeResponse: DescribeServicesCommandOutput,
): EcsClient {
  const send = vi.fn(async (cmd: unknown) => {
    if (cmd instanceof ListClustersCommand) {
      const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [clusterArn] };
      return out;
    }
    if (cmd instanceof ListServicesCommand) {
      const out: ListServicesCommandOutput = { $metadata: {}, serviceArns };
      return out;
    }
    if (cmd instanceof DescribeServicesCommand) {
      return describeResponse;
    }
    throw new Error('unexpected command');
  });
  return { send } as unknown as EcsClient;
}

describe('checkFargateImdsv2 — mixed cluster (fixture: describe-services-mixed.json)', () => {
  it('emits one Imdsv2Finding per Fargate service, skipping the EC2-launch service entirely', async () => {
    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const client = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await checkFargateImdsv2(client);

    expect(report.checked).toHaveLength(4); // 4 Fargate services; the EC2 one is skipped
    expect(report.checked.some((f) => f.serviceName === 'ec2-batch-runner')).toBe(false);
  });

  it('classifies LATEST and >= 1.4.0 as compliant; < 1.4.0 as non-compliant', async () => {
    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const client = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await checkFargateImdsv2(client);
    const by = (name: string) => report.checked.find((f) => f.serviceName === name)!;

    expect(by('web-frontend').compliant).toBe(true);
    expect(by('web-frontend').platformVersion).toBe('LATEST');
    expect(by('api-server').compliant).toBe(true);
    expect(by('api-server').platformVersion).toBe('1.4.0');
    expect(by('legacy-worker').compliant).toBe(false);
    expect(by('legacy-worker').platformVersion).toBe('1.3.0');
  });

  it('treats FARGATE_SPOT capacity-provider services as Fargate (no explicit launchType set), and an absent platformVersion as LATEST/compliant', async () => {
    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const client = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await checkFargateImdsv2(client);
    const spot = report.checked.find((f) => f.serviceName === 'spot-batch')!;

    expect(spot).toBeDefined();
    expect(spot.platformVersion).toBe('LATEST');
    expect(spot.compliant).toBe(true);
  });

  it('derives 3 compliant and 1 non-compliant from checked across the mixed fixture', async () => {
    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const client = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await checkFargateImdsv2(client);

    // Counts are derived, so "the buckets sum to checked.length" is no longer
    // an invariant worth asserting — it is true by construction. What is worth
    // asserting is that the derivation reads the fixture correctly.
    const counts = imdsv2Counts(report);
    expect(counts.compliant).toBe(3);
    expect(counts.nonCompliant).toBe(1);
  });

  it('projects serviceArn, serviceName, clusterArn, and taskDefinitionArn from the Service into the finding', async () => {
    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const client = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await checkFargateImdsv2(client);
    const api = report.checked.find((f) => f.serviceName === 'api-server')!;

    expect(api.serviceArn).toBe('arn:aws:ecs:us-east-1:111122223333:service/prod/api-server');
    expect(api.clusterArn).toBe(PROD_CLUSTER_ARN);
    expect(api.taskDefinitionArn).toBe('arn:aws:ecs:us-east-1:111122223333:task-definition/api-server:7');
  });
});

describe('checkFargateImdsv2 — empty account', () => {
  it('returns an empty checked array and zero counts when no clusters exist', async () => {
    const client = makeClient<EcsClient>((cmd) => {
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [] };
        return out;
      }
      throw new Error('unexpected command');
    });

    const report = await checkFargateImdsv2(client);

    expect(report.checked).toEqual([]);
    expect(imdsv2Counts(report)).toEqual({ compliant: 0, nonCompliant: 0 });
  });

  it('skips clusters that contain no services without making a DescribeServices call', async () => {
    const sends: string[] = [];
    const send = vi.fn(async (cmd: unknown) => {
      sends.push(cmd!.constructor.name);
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [PROD_CLUSTER_ARN] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        const out: ListServicesCommandOutput = { $metadata: {}, serviceArns: [] };
        return out;
      }
      throw new Error('unexpected command');
    });
    const client = { send } as unknown as EcsClient;

    const report = await checkFargateImdsv2(client);

    expect(report.checked).toEqual([]);
    expect(sends).not.toContain('DescribeServicesCommand');
  });
});

describe('checkFargateImdsv2 — pagination', () => {
  it('walks ListClusters nextToken across two pages', async () => {
    const clusterA = 'arn:aws:ecs:us-east-1:111122223333:cluster/a';
    const clusterB = 'arn:aws:ecs:us-east-1:111122223333:cluster/b';

    let listClustersCalls = 0;
    const send = vi.fn(async (cmd: unknown) => {
      if (cmd instanceof ListClustersCommand) {
        listClustersCalls += 1;
        const input = cmd.input as { nextToken?: string };
        if (!input.nextToken) {
          const out: ListClustersCommandOutput = {
            $metadata: {},
            clusterArns: [clusterA],
            nextToken: 'cursor-2',
          };
          return out;
        }
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [clusterB] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        const out: ListServicesCommandOutput = { $metadata: {}, serviceArns: [] };
        return out;
      }
      throw new Error('unexpected command');
    });
    const client = { send } as unknown as EcsClient;

    const report = await checkFargateImdsv2(client);

    expect(listClustersCalls).toBe(2);
    expect(report.checked).toEqual([]);
  });

  it('walks ListServices nextToken within a single cluster', async () => {
    let listServicesCalls = 0;
    const send = vi.fn(async (cmd: unknown) => {
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [PROD_CLUSTER_ARN] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        listServicesCalls += 1;
        const input = cmd.input as { nextToken?: string };
        if (!input.nextToken) {
          const out: ListServicesCommandOutput = {
            $metadata: {},
            serviceArns: ['arn:aws:ecs:us-east-1:111122223333:service/prod/s1'],
            nextToken: 'svc-cursor-2',
          };
          return out;
        }
        const out: ListServicesCommandOutput = {
          $metadata: {},
          serviceArns: ['arn:aws:ecs:us-east-1:111122223333:service/prod/s2'],
        };
        return out;
      }
      if (cmd instanceof DescribeServicesCommand) {
        const input = cmd.input as { services?: string[] };
        const services = (input.services ?? []).map((arn) => ({
          serviceArn: arn,
          serviceName: arn.split('/').pop()!,
          clusterArn: PROD_CLUSTER_ARN,
          launchType: 'FARGATE',
          platformVersion: 'LATEST',
          taskDefinition: 'arn:aws:ecs:us-east-1:111122223333:task-definition/fam:1',
        }));
        const out: DescribeServicesCommandOutput = { $metadata: {}, services };
        return out;
      }
      throw new Error('unexpected command');
    });
    const client = { send } as unknown as EcsClient;

    const report = await checkFargateImdsv2(client);

    expect(listServicesCalls).toBe(2);
    expect(report.checked.map((f) => f.serviceName).sort()).toEqual(['s1', 's2']);
  });

  it('chunks DescribeServices calls into batches of at most 10 service ARNs', async () => {
    const serviceArns = Array.from(
      { length: 23 },
      (_, i) => `arn:aws:ecs:us-east-1:111122223333:service/prod/svc-${i}`,
    );
    const describeCalls: number[] = [];
    const send = vi.fn(async (cmd: unknown) => {
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [PROD_CLUSTER_ARN] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        const out: ListServicesCommandOutput = { $metadata: {}, serviceArns };
        return out;
      }
      if (cmd instanceof DescribeServicesCommand) {
        const input = cmd.input as { services?: string[] };
        const batch = input.services ?? [];
        describeCalls.push(batch.length);
        const services = batch.map((arn) => ({
          serviceArn: arn,
          serviceName: arn.split('/').pop()!,
          clusterArn: PROD_CLUSTER_ARN,
          launchType: 'FARGATE',
          platformVersion: 'LATEST',
        }));
        const out: DescribeServicesCommandOutput = { $metadata: {}, services };
        return out;
      }
      throw new Error('unexpected command');
    });
    const client = { send } as unknown as EcsClient;

    const report = await checkFargateImdsv2(client);

    // 23 services with batch size 10 → calls of 10, 10, 3.
    expect(describeCalls).toEqual([10, 10, 3]);
    expect(report.checked).toHaveLength(23);
    expect(describeCalls.every((n) => n <= 10)).toBe(true);
  });
});

describe('checkFargateImdsv2 — error wrapping', () => {
  it('throws an error naming the Fargate check when ListClusters rejects', async () => {
    const client = makeClient<EcsClient>((cmd) => {
      if (cmd instanceof ListClustersCommand) {
        throw new Error('Throttling: rate exceeded on ListClusters');
      }
      throw new Error('unexpected command');
    });

    await expect(checkFargateImdsv2(client)).rejects.toThrow(/checkFargateImdsv2/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(/Fargate/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(/ListClusters/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(/Throttling/);
  });

  it('throws an error naming the Fargate check and the offending cluster ARN when ListServices rejects', async () => {
    const client = makeClient<EcsClient>((cmd) => {
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [PROD_CLUSTER_ARN] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        throw new Error('ClusterNotFoundException: cluster gone');
      }
      throw new Error('unexpected command');
    });

    await expect(checkFargateImdsv2(client)).rejects.toThrow(/checkFargateImdsv2/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(/ListServices/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(PROD_CLUSTER_ARN);
  });

  it('throws an error naming the Fargate check and the cluster ARN when DescribeServices rejects', async () => {
    const arn = 'arn:aws:ecs:us-east-1:111122223333:service/prod/broken';
    const client = makeClient<EcsClient>((cmd) => {
      if (cmd instanceof ListClustersCommand) {
        const out: ListClustersCommandOutput = { $metadata: {}, clusterArns: [PROD_CLUSTER_ARN] };
        return out;
      }
      if (cmd instanceof ListServicesCommand) {
        const out: ListServicesCommandOutput = { $metadata: {}, serviceArns: [arn] };
        return out;
      }
      if (cmd instanceof DescribeServicesCommand) {
        throw new Error('AccessDeniedException: not allowed on DescribeServices');
      }
      throw new Error('unexpected command');
    });

    await expect(checkFargateImdsv2(client)).rejects.toThrow(/checkFargateImdsv2/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(/DescribeServices/);
    await expect(checkFargateImdsv2(client)).rejects.toThrow(PROD_CLUSTER_ARN);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// runAwsContextChecks composite orchestrator
// ─────────────────────────────────────────────────────────────────────────────

describe('runAwsContextChecks — composition', () => {
  it('composes ALB presence and Fargate IMDSv2 reports into a single AwsContextReport', async () => {
    const elbClient = makeClient<AlbClient>((cmd) => {
      if (cmd instanceof DescribeLoadBalancersCommand) return lbMixedResponse;
      throw new Error('unexpected command');
    });

    const serviceArns = (describeServicesMixed.services ?? []).map((s) => s.serviceArn!);
    const ecsClient = makeSingleClusterEcsClient(PROD_CLUSTER_ARN, serviceArns, describeServicesMixed);

    const report = await runAwsContextChecks(elbClient, ecsClient);

    expect(report.alb.albArns).toHaveLength(2);
    expect(report.imdsv2.checked).toHaveLength(4);
    expect(imdsv2Counts(report.imdsv2)).toEqual({ compliant: 3, nonCompliant: 1 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — anchored shape assertions
// ─────────────────────────────────────────────────────────────────────────────

describe('AWS fixture — describe-services-mixed.json', () => {
  it('contains 4 Fargate services (3 by launchType, 1 by FARGATE_SPOT capacity provider) and 1 EC2 service', () => {
    const services = describeServicesMixed.services ?? [];
    const fargateByLaunch = services.filter((s) => s.launchType === 'FARGATE').length;
    const fargateByCapacity = services.filter((s) =>
      (s.capacityProviderStrategy ?? []).some(
        (p) => p.capacityProvider === 'FARGATE' || p.capacityProvider === 'FARGATE_SPOT',
      ),
    ).length;
    const ec2 = services.filter((s) => s.launchType === 'EC2').length;

    expect(fargateByLaunch).toBe(3);
    expect(fargateByCapacity).toBe(1);
    expect(ec2).toBe(1);
  });
});

describe('AWS fixture — describe-load-balancers-mixed.json', () => {
  it('contains exactly 2 ALBs and 1 NLB (drives the filtering test)', () => {
    const lbs = lbMixedResponse.LoadBalancers ?? [];
    expect(lbs.filter((lb) => lb.Type === 'application')).toHaveLength(2);
    expect(lbs.filter((lb) => lb.Type === 'network')).toHaveLength(1);
  });
});
