import { graphql } from '@octokit/graphql';
import type { Advisory, Ecosystem } from './types.js';

// Minimal callable interface for the graphql client.
// Accepting an optional third argument lets tests inject a mock without needing
// a real GITHUB_TOKEN or hitting the live API. When no client is provided, the
// function builds an authenticated client from GITHUB_TOKEN and validates the token
// before making any network call. The token check is intentionally skipped when a
// client is injected — the caller owns auth in that case.
type GraphqlClient = (query: string, variables: Record<string, unknown>) => Promise<unknown>;

interface GraphqlResponse {
  securityAdvisories: {
    nodes: Advisory[];
  };
}

const QUERY = `
  query FetchAdvisories($since: DateTime!, $ecosystem: SecurityAdvisoryEcosystem!) {
    securityAdvisories(
      first: 100
      orderBy: { field: PUBLISHED_AT, direction: DESC }
      publishedSince: $since
    ) {
      nodes {
        ghsaId
        summary
        severity
        cvss {
          score
        }
        vulnerabilities(first: 10, ecosystem: $ecosystem) {
          nodes {
            package {
              name
              ecosystem
            }
            vulnerableVersionRange
            firstPatchedVersion {
              identifier
            }
          }
        }
      }
    }
  }
`;

export async function fetchRecentAdvisories(
  sinceISO: string,
  ecosystem: Ecosystem,
  client?: GraphqlClient,
): Promise<Advisory[]> {
  let gql: GraphqlClient;

  if (client !== undefined) {
    gql = client;
  } else {
    const token = process.env['GITHUB_TOKEN'];
    if (!token) {
      throw new Error(
        'GITHUB_TOKEN is not set. ' +
          'Add it as a GitHub Actions secret (Settings → Secrets) or in your local .env file.',
      );
    }
    gql = graphql.defaults({
      headers: { authorization: `token ${token}` },
    }) as unknown as GraphqlClient;
  }

  const response = (await gql(QUERY, { since: sinceISO, ecosystem })) as GraphqlResponse;
  return response.securityAdvisories.nodes;
}
