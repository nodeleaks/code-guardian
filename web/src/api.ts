export type ScanStatus = 'QUEUED' | 'SCANNING' | 'FINISHED' | 'FAILED';

export interface Vulnerability {
  id: string;
  vulnerabilityId: string;
  pkgName: string;
  installedVersion: string | null;
  fixedVersion: string | null;
  severity: string;
  title: string | null;
  target: string;
}

export interface Scan {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  criticalVulnerabilities: Vulnerability[];
  criticalVulnerabilityCount: number;
  criticalVulnerabilitiesTruncated: boolean;
  errorMessage: string | null;
}

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/graphql';

async function graphqlRequest<T>(query: string, variables: Record<string, unknown>): Promise<T> {
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });

  if (!res.ok) {
    throw new Error(`GraphQL request failed: HTTP ${res.status}`);
  }

  const body = (await res.json()) as { data?: T; errors?: { message: string }[] };
  if (body.errors?.length) {
    throw new Error(body.errors.map((e) => e.message).join('; '));
  }
  if (!body.data) {
    throw new Error('GraphQL response had no data');
  }
  return body.data;
}

const START_SCAN_MUTATION = /* GraphQL */ `
  mutation StartScan($repositoryUrl: String!) {
    startScan(input: { repositoryUrl: $repositoryUrl }) {
      id
      status
    }
  }
`;

const SCAN_QUERY = /* GraphQL */ `
  query GetScan($id: ID!) {
    scan(id: $id) {
      id
      repositoryUrl
      status
      criticalVulnerabilityCount
      criticalVulnerabilitiesTruncated
      errorMessage
      criticalVulnerabilities {
        id
        vulnerabilityId
        pkgName
        installedVersion
        fixedVersion
        severity
        title
        target
      }
    }
  }
`;

export async function startScan(repositoryUrl: string): Promise<Pick<Scan, 'id' | 'status'>> {
  const data = await graphqlRequest<{ startScan: Pick<Scan, 'id' | 'status'> }>(
    START_SCAN_MUTATION,
    { repositoryUrl },
  );
  return data.startScan;
}

export async function getScan(id: string): Promise<Scan | null> {
  const data = await graphqlRequest<{ scan: Scan | null }>(SCAN_QUERY, { id });
  return data.scan;
}
