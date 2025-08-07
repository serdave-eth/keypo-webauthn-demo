import { LogEntry } from '@/types/auth';

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

interface LogOptions {
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  error?: string;
  metadata?: Record<string, any>;
}

class Logger {
  private readonly logLevel: LogLevel;

  constructor() {
    const envLogLevel = process.env.LOG_LEVEL?.toUpperCase() as LogLevel;
    this.logLevel = envLogLevel || 'INFO';
  }

  private shouldLog(level: LogLevel): boolean {
    const levels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
    return levels[level] >= levels[this.logLevel];
  }

  private createLogEntry(level: LogLevel, event: string, options: LogOptions = {}): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      event,
      userId: options.userId,
      sessionId: options.sessionId,
      ipAddress: options.ipAddress,
      userAgent: options.userAgent,
      error: options.error,
      metadata: options.metadata,
    };
  }

  private writeLog(logEntry: LogEntry): void {
    const logString = JSON.stringify(logEntry, null, 2);
    console.log(logString);
  }

  debug(event: string, options: LogOptions = {}): void {
    if (this.shouldLog('DEBUG')) {
      this.writeLog(this.createLogEntry('DEBUG', event, options));
    }
  }

  info(event: string, options: LogOptions = {}): void {
    if (this.shouldLog('INFO')) {
      this.writeLog(this.createLogEntry('INFO', event, options));
    }
  }

  warn(event: string, options: LogOptions = {}): void {
    if (this.shouldLog('WARN')) {
      this.writeLog(this.createLogEntry('WARN', event, options));
    }
  }

  error(event: string, options: LogOptions = {}): void {
    if (this.shouldLog('ERROR')) {
      this.writeLog(this.createLogEntry('ERROR', event, options));
    }
  }

  // WebAuthn specific logging methods
  logRegistrationAttempt(sessionId: string, ipAddress?: string, userAgent?: string): void {
    this.info('webauthn_registration_attempt', {
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logRegistrationSuccess(userId: string, sessionId: string, authenticatorData: any, ipAddress?: string, userAgent?: string): void {
    this.info('webauthn_registration_success', {
      userId,
      sessionId,
      ipAddress,
      userAgent,
      metadata: { authenticatorData },
    });
  }

  logRegistrationFailure(sessionId: string, error: string, ipAddress?: string, userAgent?: string): void {
    this.error('webauthn_registration_failure', {
      sessionId,
      ipAddress,
      userAgent,
      error,
    });
  }

  logAuthenticationAttempt(sessionId: string, ipAddress?: string, userAgent?: string): void {
    this.info('webauthn_authentication_attempt', {
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logAuthenticationSuccess(userId: string, sessionId: string, ipAddress?: string, userAgent?: string): void {
    this.info('webauthn_authentication_success', {
      userId,
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logAuthenticationFailure(sessionId: string, error: string, ipAddress?: string, userAgent?: string): void {
    this.error('webauthn_authentication_failure', {
      sessionId,
      ipAddress,
      userAgent,
      error,
    });
  }

  logJWTIssued(userId: string, sessionId: string, ipAddress?: string, userAgent?: string): void {
    this.info('jwt_token_issued', {
      userId,
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logJWTValidationSuccess(userId: string, sessionId?: string, ipAddress?: string, userAgent?: string): void {
    this.debug('jwt_validation_success', {
      userId,
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logJWTValidationFailure(error: string, sessionId?: string, ipAddress?: string, userAgent?: string): void {
    this.warn('jwt_validation_failure', {
      sessionId,
      ipAddress,
      userAgent,
      error,
    });
  }

  logUserSignOut(userId: string, sessionId?: string, ipAddress?: string, userAgent?: string): void {
    this.info('user_signout', {
      userId,
      sessionId,
      ipAddress,
      userAgent,
    });
  }

  logTokenExpiration(userId: string, sessionId?: string): void {
    this.info('jwt_token_expired', {
      userId,
      sessionId,
    });
  }

  logRateLimitTriggered(ipAddress: string, endpoint: string, userAgent?: string): void {
    this.warn('rate_limit_triggered', {
      ipAddress,
      userAgent,
      metadata: { endpoint },
    });
  }

  logDatabaseError(operation: string, error: string, userId?: string): void {
    this.error('database_operation_failed', {
      userId,
      error,
      metadata: { operation },
    });
  }
}

export const logger = new Logger();