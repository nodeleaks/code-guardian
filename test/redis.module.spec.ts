import { EventEmitter } from 'node:events';

/**
 * Regression test for the crash path: ioredis' client is an EventEmitter,
 * and Node throws on an 'error' event with no listener registered - which
 * would take the whole process down on any transient Redis failure. The
 * module must attach a listener at construction time.
 */
jest.mock('ioredis', () => ({
  __esModule: true,
  default: jest.fn(() => new EventEmitter()),
}));

import Redis from 'ioredis';
import { RedisModule } from '../src/redis/redis.module';
import { REDIS_CLIENT } from '../src/redis/redis.constants';

interface RedisOptions {
  host: string;
  port: number;
  password?: string;
  tls?: Record<string, unknown>;
}

type ClientFactory = (config: { get: (key: string) => unknown }) => EventEmitter;

const mockRedis = Redis as unknown as jest.Mock<EventEmitter, [RedisOptions]>;

function buildClient(overrides: Record<string, unknown> = {}): EventEmitter {
  const providers = Reflect.getMetadata('providers', RedisModule) as {
    provide: symbol;
    useFactory: ClientFactory;
  }[];
  const provider = providers.find((p) => p.provide === REDIS_CLIENT);
  if (!provider) {
    throw new Error('REDIS_CLIENT provider not found on RedisModule');
  }

  const values: Record<string, unknown> = {
    'redis.host': 'localhost',
    'redis.port': 6379,
    'redis.password': undefined,
    'redis.tls': false,
    ...overrides,
  };

  return provider.useFactory({ get: (key: string) => values[key] });
}

describe('RedisModule client factory', () => {
  afterEach(() => jest.clearAllMocks());

  it("registers an 'error' listener so a connection error cannot crash the process", () => {
    const client = buildClient();

    expect(client.listenerCount('error')).toBeGreaterThan(0);
    // Without a listener this emit would throw - that is the bug being guarded.
    expect(() => client.emit('error', new Error('ECONNREFUSED'))).not.toThrow();
  });

  it('omits password and tls when not configured', () => {
    buildClient();

    const options = mockRedis.mock.calls[0][0];
    expect(options).not.toHaveProperty('password');
    expect(options).not.toHaveProperty('tls');
  });

  it('passes password and tls through when configured', () => {
    buildClient({ 'redis.password': 's3cret', 'redis.tls': true });

    const options = mockRedis.mock.calls[0][0];
    expect(options.password).toBe('s3cret');
    expect(options.tls).toEqual({});
  });
});
