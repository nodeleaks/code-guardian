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

/**
 * Status and counts only. The findings are fetched separately and a page at a
 * time (see getVulnerabilities) - they are not part of this shape, so the
 * 2-second poll stays small no matter how many findings a scan produced.
 */
export interface Scan {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  criticalVulnerabilityCount: number;
  errorMessage: string | null;
}

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/graphql';

// Mirrors StartScanInput's server-side validation
// (src/scan/dto/start-scan.input.ts) so obviously-bad input gets an
// immediate, specific message instead of a round trip to the API. The
// server remains the source of truth - this is just a fast-path UX check.
const GITHUB_REPO_URL_REGEX = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(?:\.git)?\/?$/;

export function isValidRepositoryUrl(url: string): boolean {
  return GITHUB_REPO_URL_REGEX.test(url);
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

interface GraphQLError {
  message: string;
  extensions?: {
    originalError?: { message?: string | string[] };
  };
}

interface GraphQLResponse<T> {
  data?: T;
  errors?: GraphQLError[];
}

function isGraphQLError(value: unknown): value is GraphQLError {
  if (typeof value !== 'object' || value === null) return false;

  const record = value as Record<string, unknown>;
  return typeof record.message === 'string';
}

function isGraphQLResponse<T>(value: unknown): value is GraphQLResponse<T> {
  if (typeof value !== 'object' || value === null) return false;

  const record = value as Record<string, unknown>;
  if ('errors' in record) {
    if (!Array.isArray(record.errors) || !record.errors.every(isGraphQLError)) return false;
  }

  return true;
}

// NestJS's ValidationPipe (used for StartScanInput) reports the actual
// class-validator message(s) under extensions.originalError.message, not
// in the top-level `message` field - GraphQL wraps that as the generic
// "Bad Request Exception". Prefer the specific one so a user who somehow
// gets past the client-side URL check (isValidRepositoryUrl) still sees
// why the server rejected it, not just "Bad Request Exception".
function describeGraphQLError(err: GraphQLError): string {
  const original = err.extensions?.originalError?.message;
  if (Array.isArray(original) && original.length > 0) return original.join('; ');
  if (typeof original === 'string') return original;
  return err.message;
}

async function graphqlRequest<T>(query: string, variables: Record<string, unknown>): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables }),
    });
  } catch {
    // fetch() only throws on network-level failures (server down, DNS,
    // CORS preflight rejection, offline) - HTTP error statuses land below.
    throw new Error(`Could not reach the API at ${API_URL}. Is the server running?`);
  }

  if (!res.ok) {
    throw new Error(`GraphQL request failed: HTTP ${res.status}`);
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch {
    throw new Error('The API returned a response that was not valid JSON.');
  }

  if (!isGraphQLResponse<T>(json)) {
    throw new Error('The API returned a JSON payload in an unexpected shape.');
  }
  const body = json;

  if (body.errors?.length) {
    throw new Error(body.errors.map(describeGraphQLError).join('; '));
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
      errorMessage
    }
  }
`;

const VULNERABILITIES_QUERY = /* GraphQL */ `
  query GetVulnerabilities($id: ID!, $offset: Int!, $limit: Int!) {
    scan(id: $id) {
      id
      criticalVulnerabilities(offset: $offset, limit: $limit) {
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

/**
 * One page of a scan's findings. The server caps `limit` (see
 * VulnerabilityPageArgs), so asking for more than it allows is a validation
 * error rather than a very large response.
 */
export async function getVulnerabilities(
  id: string,
  offset: number,
  limit: number,
): Promise<Vulnerability[]> {
  const data = await graphqlRequest<{
    scan: { criticalVulnerabilities: Vulnerability[] } | null;
  }>(VULNERABILITIES_QUERY, { id, offset, limit });
  return data.scan?.criticalVulnerabilities ?? [];
}
