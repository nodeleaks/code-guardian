import configuration from '../src/config/configuration';

describe('Configuration', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('defaults (no env vars set)', () => {
    beforeEach(() => {
      delete process.env.PORT;
      delete process.env.REDIS_HOST;
      delete process.env.REDIS_PORT;
      delete process.env.TRIVY_BINARY_PATH;
      delete process.env.SCAN_RECORD_TTL_SECONDS;
      delete process.env.CORS_ORIGIN;
    });

    it('uses port 3000', () => {
      const config = configuration();
      expect(config.port).toBe(3000);
    });

    it('uses localhost for redis', () => {
      const config = configuration();
      expect(config.redis.host).toBe('localhost');
      expect(config.redis.port).toBe(6379);
    });

    it('uses trivy binary name', () => {
      const config = configuration();
      expect(config.trivy.binaryPath).toBe('trivy');
    });

    it('uses 86400 seconds (1 day) TTL', () => {
      const config = configuration();
      expect(config.scan.recordTtlSeconds).toBe(86400);
    });

    it('uses default CORS origin http://localhost:5173', () => {
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://localhost:5173']);
    });
  });

  describe('environment variable overrides', () => {
    it('parses PORT as number', () => {
      process.env.PORT = '8080';
      const config = configuration();
      expect(config.port).toBe(8080);
      expect(typeof config.port).toBe('number');
    });

    it('overrides REDIS_HOST', () => {
      process.env.REDIS_HOST = 'redis.example.com';
      const config = configuration();
      expect(config.redis.host).toBe('redis.example.com');
    });

    it('parses REDIS_PORT as number', () => {
      process.env.REDIS_PORT = '6380';
      const config = configuration();
      expect(config.redis.port).toBe(6380);
      expect(typeof config.redis.port).toBe('number');
    });

    it('overrides TRIVY_BINARY_PATH', () => {
      process.env.TRIVY_BINARY_PATH = '/usr/bin/trivy';
      const config = configuration();
      expect(config.trivy.binaryPath).toBe('/usr/bin/trivy');
    });

    it('parses SCAN_RECORD_TTL_SECONDS as number', () => {
      process.env.SCAN_RECORD_TTL_SECONDS = '3600';
      const config = configuration();
      expect(config.scan.recordTtlSeconds).toBe(3600);
      expect(typeof config.scan.recordTtlSeconds).toBe('number');
    });
  });

  describe('CORS_ORIGIN comma-split edge cases', () => {
    it('single origin, no comma', () => {
      process.env.CORS_ORIGIN = 'http://localhost:3000';
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://localhost:3000']);
    });

    it('multiple comma-separated origins', () => {
      process.env.CORS_ORIGIN = 'http://localhost:3000,http://localhost:5173,https://example.com';
      const config = configuration();
      expect(config.cors.origin).toEqual([
        'http://localhost:3000',
        'http://localhost:5173',
        'https://example.com',
      ]);
    });

    it('trims whitespace around commas', () => {
      process.env.CORS_ORIGIN = ' http://a.com , http://b.com ';
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://a.com', 'http://b.com']);
    });

    it('filters out empty segments from consecutive commas', () => {
      process.env.CORS_ORIGIN = 'http://a.com,,http://b.com';
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://a.com', 'http://b.com']);
    });

    it('filters out trailing comma', () => {
      process.env.CORS_ORIGIN = 'http://a.com,';
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://a.com']);
    });

    it('filters out empty string set', () => {
      process.env.CORS_ORIGIN = '';
      const config = configuration();
      expect(config.cors.origin).toEqual([]);
    });

    it('handles leading comma', () => {
      process.env.CORS_ORIGIN = ',http://a.com';
      const config = configuration();
      expect(config.cors.origin).toEqual(['http://a.com']);
    });
  });

  it('returns the full AppConfig shape', () => {
    const config = configuration();
    expect(config).toHaveProperty('port');
    expect(config).toHaveProperty('redis');
    expect(config).toHaveProperty('trivy');
    expect(config).toHaveProperty('scan');
    expect(config).toHaveProperty('cors');
  });
});
