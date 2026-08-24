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
});
