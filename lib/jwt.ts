import jwt from 'jsonwebtoken';
import { User } from '@/types/auth';

interface JWTPayload {
  userId: string;
  email?: string;
  username?: string;
  iat?: number;
  exp?: number;
}

class JWTManager {
  private readonly secret: string;
  private readonly expirationTime: string;

  constructor() {
    this.secret = process.env.JWT_SECRET || 'fallback-secret-for-development';
    this.expirationTime = process.env.JWT_EXPIRATION || '1h';
    
    if (!process.env.JWT_SECRET) {
      console.warn('JWT_SECRET not set, using fallback secret for development');
    }
  }

  /**
   * Generate a JWT token for the given user
   */
  generateToken(user: User): string {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      username: user.username,
    };

    return jwt.sign(payload, this.secret, {
      expiresIn: this.expirationTime,
      issuer: 'webauthn-demo',
      audience: 'webauthn-demo-users',
    } as jwt.SignOptions);
  }

  /**
   * Verify and decode a JWT token
   */
  verifyToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, this.secret, {
        issuer: 'webauthn-demo',
        audience: 'webauthn-demo-users',
      }) as JWTPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        console.error('JWT verification failed:', error.message);
      } else if (error instanceof jwt.TokenExpiredError) {
        console.error('JWT token expired:', error.message);
      } else {
        console.error('JWT verification error:', error);
      }
      return null;
    }
  }

  /**
   * Decode a JWT token without verification (for debugging)
   */
  decodeToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.decode(token) as JWTPayload;
      return decoded;
    } catch (error) {
      console.error('JWT decode error:', error);
      return null;
    }
  }

  /**
   * Check if a token is expired
   */
  isTokenExpired(token: string): boolean {
    const decoded = this.decodeToken(token);
    if (!decoded || !decoded.exp) {
      return true;
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  }

  /**
   * Get remaining time until token expires (in seconds)
   */
  getTokenExpirationTime(token: string): number | null {
    const decoded = this.decodeToken(token);
    if (!decoded || !decoded.exp) {
      return null;
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    return Math.max(0, decoded.exp - currentTime);
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader: string | null): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    
    return authHeader.substring(7); // Remove "Bearer " prefix
  }
}

export const jwtManager = new JWTManager();