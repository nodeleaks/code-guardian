export interface AppConfig {
  port: number;
  redis: {
    host: string;
    port: number;
    password?: string;
    tls: boolean;
  };
  trivy: {
    binaryPath: string;
  };
  scan: {
    recordTtlSeconds: number;
    /** Hard wall-clock cap on `git clone` and on `trivy fs`, each. */
    timeoutMs: number;
    /** Reject a clone whose working tree exceeds this, before running trivy. */
    maxRepoSizeMb: number;
    /** Refuse new scans once this many jobs are already waiting. */
    maxQueueDepth: number;
  };
  cors: {
    origin: string[];
  };
  graphql: {
    /** Serves the Apollo landing page AND enables introspection. */
    playground: boolean;
  };
}

// Number(), not parseInt(): this file re-reads process.env independently of
// the Joi schema in app.module.ts, and @nestjs/config only writes Joi's
// coerced values back for variables that weren't already set - so for any
// variable an operator actually set, these two parsers have to agree.
// parseInt doesn't: it reads "1e5" as 1 and "0.5" as 0, both of which Joi
// happily accepts, which is how a validated config still produced a 1ms
// timeout or `SET ... EX 0`. Number matches Joi's own coercion, and anything
// it would read differently (e.g. "0x10") Joi rejects at boot first.
const asNumber = (value: string | undefined, fallback: number): number =>
  value === undefined ? fallback : Number(value);

export default (): AppConfig => ({
  port: asNumber(process.env.PORT, 3000),
  redis: {
    host: process.env.REDIS_HOST ?? 'localhost',
    port: asNumber(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || undefined,
    tls: process.env.REDIS_TLS === 'true',
  },
  trivy: {
    binaryPath: process.env.TRIVY_BINARY_PATH ?? 'trivy',
  },
  scan: {
    recordTtlSeconds: asNumber(process.env.SCAN_RECORD_TTL_SECONDS, 86400),
    timeoutMs: asNumber(process.env.SCAN_TIMEOUT_MS, 300000),
    maxRepoSizeMb: asNumber(process.env.SCAN_MAX_REPO_SIZE_MB, 1024),
    maxQueueDepth: asNumber(process.env.SCAN_MAX_QUEUE_DEPTH, 100),
  },
  cors: {
    // Comma-separated list of allowed origins for the React frontend (see
    // web/). Defaults to Vite's default dev port so `npm run dev` in web/
    // works against a locally-run API with zero config.
    origin: (process.env.CORS_ORIGIN ?? 'http://localhost:5173')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
  },
  graphql: {
    // Defaults to OFF. Previously this was hardcoded `true`, which left the
    // landing page and introspection exposed on every run path that doesn't
    // happen to set NODE_ENV=production (e.g. `npm run start:prod`).
    playground: process.env.GRAPHQL_PLAYGROUND === 'true',
  },
});
