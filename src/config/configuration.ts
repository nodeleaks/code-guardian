export interface AppConfig {
  port: number;
  redis: {
    host: string;
    port: number;
  };
  trivy: {
    binaryPath: string;
  };
  scan: {
    recordTtlSeconds: number;
  };
  cors: {
    origin: string[];
  };
}

export default (): AppConfig => ({
  port: parseInt(process.env.PORT ?? '3000', 10),
  redis: {
    host: process.env.REDIS_HOST ?? 'localhost',
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  },
  trivy: {
    binaryPath: process.env.TRIVY_BINARY_PATH ?? 'trivy',
  },
  scan: {
    recordTtlSeconds: parseInt(process.env.SCAN_RECORD_TTL_SECONDS ?? '86400', 10),
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
});
