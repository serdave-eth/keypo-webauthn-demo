import { NextRequest, NextResponse } from 'next/server';
import { verifyAuthenticationResponse, getWebAuthnConfig, type AuthenticationResponseJSON, type VerifyAuthenticationResponseOpts } from '@/lib/webauthn';
import { db } from '@/lib/db';
import { jwtManager } from '@/lib/jwt';
import { logger } from '@/lib/logger';

export async function POST(request: NextRequest) {
  try {
    const ipAddress = request.headers.get('x-forwarded-for') || 
                      request.headers.get('x-real-ip') || 
                      'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Get session from cookie or body
    const sessionId = request.cookies.get('webauthn-session')?.value;
    const body = await request.json();
    const { credential, sessionId: bodySessionId }: {
      credential: AuthenticationResponseJSON;
      sessionId?: string;
    } = body;

    const finalSessionId = sessionId || bodySessionId;

    if (!finalSessionId) {
      logger.logAuthenticationFailure('unknown', 'No session ID provided', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Session not found',
      }, { status: 400 });
    }

    if (!credential) {
      logger.logAuthenticationFailure(finalSessionId, 'Missing credential', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Missing credential',
      }, { status: 400 });
    }

    // Get the stored challenge
    const expectedChallenge = db.getChallenge(finalSessionId);
    if (!expectedChallenge) {
      logger.logAuthenticationFailure(finalSessionId, 'Challenge not found or expired', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Challenge not found or expired',
      }, { status: 400 });
    }

    // Find the authenticator by credential ID
    const credentialIdBuffer = Buffer.from(credential.id, 'base64url');
    const authenticator = db.getAuthenticatorByCredentialId(credentialIdBuffer);
    
    if (!authenticator) {
      logger.logAuthenticationFailure(finalSessionId, 'Authenticator not found', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Authenticator not found',
      }, { status: 404 });
    }

    // Get the user
    const user = db.getUserById(authenticator.userId);
    if (!user) {
      logger.logAuthenticationFailure(finalSessionId, 'User not found', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'User not found',
      }, { status: 404 });
    }

    const { rpID, origin } = getWebAuthnConfig();

    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: Buffer.from(authenticator.credentialId).toString('base64url'),
        publicKey: new Uint8Array(authenticator.publicKey),
        counter: authenticator.counter,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      logger.logAuthenticationFailure(finalSessionId, 'Authentication verification failed', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Authentication verification failed',
      }, { status: 400 });
    }

    // Update the authenticator counter
    db.updateAuthenticator(authenticator.id, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: new Date(),
    });

    // Update user's last login
    db.updateUser(user.id, {
      lastLoginAt: new Date(),
    });

    // Generate JWT token
    const token = jwtManager.generateToken(user);

    // Clean up the challenge
    db.deleteChallenge(finalSessionId);

    logger.logAuthenticationSuccess(user.id, finalSessionId, ipAddress, userAgent);
    logger.logJWTIssued(user.id, finalSessionId, ipAddress, userAgent);

    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      token,
    });

    // Set JWT in httpOnly cookie
    response.cookies.set('auth-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60, // 1 hour
    });

    // Clear the session cookie
    response.cookies.set('webauthn-session', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 0, // Delete the cookie
    });

    return response;

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    logger.error('webauthn_authentication_verification_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      error: 'Authentication failed',
    }, { status: 500 });
  }
}