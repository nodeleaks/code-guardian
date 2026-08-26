import * as Joi from 'joi';

/**
 * Boot-time validation of the environment, applied by ConfigModule in
 * app.module.ts.
 *
 * Fail at boot on a malformed value rather than silently producing NaN -
 * `PORT=abc` would otherwise reach app.listen(NaN) and bind a random port,
 * and a bad TTL would reach `SET ... EX NaN` and make every scan fail at
 * runtime with no startup signal.
 *
 * `.integer()` and `.max()` on the SCAN_* variables are load-bearing rather
 * than decoration: `.positive()` alone accepts 0.5, which parses to 0 at
 * runtime, and an out-of-range TTL reaches Redis as an invalid `EX`
 * argument. See configuration.ts for why the runtime reads these with
 * Number() so that the two parsers can't disagree.
 *
 * Kept in its own file rather than inline in app.module.ts so it can be
 * asserted on directly - see test/configuration.spec.ts.
 */
export const envValidationSchema = Joi.object({
  PORT: Joi.number().port().default(3000),
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().allow('').optional(),
  REDIS_TLS: Joi.string().valid('true', 'false').default('false'),
  TRIVY_BINARY_PATH: Joi.string().default('trivy'),
  // Ceilings are "obviously a typo" bounds, not tuning limits: a year, an
  // hour, 50GB, and 100k queued jobs respectively.
  SCAN_RECORD_TTL_SECONDS: Joi.number().integer().positive().max(31_536_000).default(86400),
  SCAN_TIMEOUT_MS: Joi.number().integer().positive().max(3_600_000).default(300000),
  SCAN_MAX_REPO_SIZE_MB: Joi.number().integer().positive().max(51_200).default(1024),
  SCAN_MAX_QUEUE_DEPTH: Joi.number().integer().positive().max(100_000).default(100),
  CORS_ORIGIN: Joi.string().allow('').optional(),
  GRAPHQL_PLAYGROUND: Joi.string().valid('true', 'false').default('false'),
});

export const envValidationOptions = { allowUnknown: true, abortEarly: false };
