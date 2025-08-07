import { NextRequest, NextResponse } from 'next/server';
import { jwtManager } from '@/lib/jwt';
import { db } from '@/lib/db';
import { logger } from '@/lib/logger';

export async function GET(request: NextRequest) {
  try {
    const ipAddress = request.headers.get('x-forwarded-for') || 
                      request.headers.get('x-real-ip') || 
                      'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Get token from cookie or Authorization header
    const cookieToken = request.cookies.get('auth-token')?.value;
    const authHeader = request.headers.get('authorization');
    const headerToken = jwtManager.extractTokenFromHeader(authHeader);
    
    const token = cookieToken || headerToken;

    if (!token) {
      logger.logJWTValidationFailure('No token provided', crypto.randomUUID(), ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        authenticated: false,
        error: 'No token provided',
      }, { status: 401 });
    }

    // Verify the token
    const payload = jwtManager.verifyToken(token);
    
    if (!payload) {
      logger.logJWTValidationFailure('Invalid token', crypto.randomUUID(), ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        authenticated: false,
        error: 'Invalid token',
      }, { status: 401 });
    }

    // Get the user from database
    const user = db.getUserById(payload.userId);
    
    if (!user) {
      logger.logJWTValidationFailure('User not found', crypto.randomUUID(), ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        authenticated: false,
        error: 'User not found',
      }, { status: 404 });
    }

    logger.logJWTValidationSuccess(user.id, crypto.randomUUID(), ipAddress, userAgent);

    return NextResponse.json({
      success: true,
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      tokenExpiration: jwtManager.getTokenExpirationTime(token),
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    logger.error('jwt_verification_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      authenticated: false,
      error: 'Verification failed',
    }, { status: 500 });
  }
}