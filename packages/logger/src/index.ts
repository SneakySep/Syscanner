import { redactDeep } from '@syscanner/core';
import pino, { type Logger, type LoggerOptions } from 'pino';

export interface CreateLoggerOptions {
  /** Service name, e.g. "api" or "worker". */
  name: string;
  level?: string;
}

/**
 * Structured logger with mandatory redaction.
 *
 * Because Syscanner processes customer source code and detects live credentials,
 * every value that reaches the log stream is passed through `redactDeep` first.
 * Doing this in a serializer — rather than trusting call sites — means a future
 * `logger.info({ env })` cannot leak a token.
 */
export function createLogger(options: CreateLoggerOptions): Logger {
  const config: LoggerOptions = {
    name: options.name,
    level: options.level ?? process.env.LOG_LEVEL ?? 'info',
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label) => ({ level: label }),
    },
    serializers: {
      err: pino.stdSerializers.err,
      error: pino.stdSerializers.err,
      // Anything a request handler hands us is potentially hostile.
      req: (value: unknown) => redactDeep(value),
      res: (value: unknown) => redactDeep(value),
      payload: (value: unknown) => redactDeep(value),
    },
    // Belt and braces: pino's own path-based redaction for the usual suspects.
    redact: {
      paths: [
        'password',
        'passwordHash',
        'token',
        'apiKey',
        'authorization',
        'req.headers.authorization',
        'req.headers.cookie',
        '*.mfaSecretEnc',
        '*.webhookSecretEnc',
        '*.configEnc',
      ],
      censor: '[REDACTED]',
    },
  };

  return pino(config);
}

export type { Logger };
