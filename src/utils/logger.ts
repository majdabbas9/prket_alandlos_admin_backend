import pino from 'pino';
import path from 'path';

const baseLogger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport:
    process.env.NODE_ENV !== 'production'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:yyyy-mm-dd HH:MM:ss.l',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
});

/**
 * Creates a child logger pre-configured with a 'file' context attribute.
 * @param filename - Absolute file path (e.g. __filename) or relative path string.
 */
export const getLogger = (filename?: string): pino.Logger => {
  if (!filename) return baseLogger;

  let relativePath = filename;
  if (path.isAbsolute(filename)) {
    relativePath = path.relative(process.cwd(), filename).replace(/\\/g, '/');
  }

  return baseLogger.child({ file: relativePath });
};

export const createLogger = getLogger;

// Attach helper methods to baseLogger for CommonJS compatibility & ease of use
const logger = Object.assign(baseLogger, {
  getLogger,
  createLogger,
});

export default logger;
