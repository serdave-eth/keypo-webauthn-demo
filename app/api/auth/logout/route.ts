import { NextRequest, NextResponse } from 'next/server';
import { jwtManager } from '@/lib/jwt';
import { logger } from '@/lib/logger';

export async function POST(request: NextRequest) {
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

    let userId: string | undefined;
    
    if (token) {
      const payload = jwtManager.verifyToken(token);
      userId = payload?.userId;
    }

    logger.logUserSignOut(userId || 'unknown', crypto.randomUUID(), ipAddress, userAgent);

    const response = NextResponse.json({
      success: true,
      message: 'Logged out successfully',
    });

    // Clear the auth token cookie
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 0, // Delete the cookie
    });

    return response;

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    logger.error('logout_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      error: 'Logout failed',
    }, { status: 500 });
  }
}