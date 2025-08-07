export interface User {
  id: string;
  email?: string;
  username?: string;
  createdAt: Date;
  lastLoginAt?: Date;
}

export interface Authenticator {
  id: string;
  userId: string;
  credentialId: Buffer;
  publicKey: Buffer;
  counter: number;
  aaguid?: string;
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface AuthenticationResult {
  success: boolean;
  user?: User;
  token?: string;
  error?: string;
}

export interface RegistrationResult {
  success: boolean;
  user?: User;
  error?: string;
}

export interface LogEntry {
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  event: string;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  error?: string;
  metadata?: Record<string, any>;
}