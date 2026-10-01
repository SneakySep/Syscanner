import { z } from 'zod';

/**
 * Environment configuration.
 *
 * Parsed and validated once at boot: a misconfigured API must fail immediately and
 * loudly rather than discover a missing secret on the first request.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.string().default('info'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  REDIS_URL: z.string().min(1).default('redis://localhost:6379'),

  API_PORT: z.coerce.number().int().positive().default(4000),
  API_HOST: z.string().default('0.0.0.0'),
  WEB_ORIGIN: z.string().default('http://localhost:3000'),

  /**
   * Requests per minute, per tenant. Tenants are keyed by organisation rather than
   * IP so that a shared corporate egress does not throttle an entire customer.
   */
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(300),
});

export type AppConfig = z.infer<typeof envSchema>;

let cached: AppConfig | undefined;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  if (cached) return cached;

  const result = envSchema.safeParse(env);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '<root>'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid API configuration:\n${details}`);
  }

  cached = result.data;
  return cached;
}
