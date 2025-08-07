import { NextRequest, NextResponse } from 'next/server';
import { verifyRegistrationResponse, getWebAuthnConfig, type RegistrationResponseJSON } from '@/lib/webauthn';
import { db } from '@/lib/db';
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
    const { credential, userId, sessionId: bodySessionId }: {
      credential: RegistrationResponseJSON;
      userId: string;
      sessionId?: string;
    } = body;

    const finalSessionId = sessionId || bodySessionId;

    if (!finalSessionId) {
      logger.logRegistrationFailure('unknown', 'No session ID provided', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Session not found',
      }, { status: 400 });
    }

    if (!credential || !userId) {
      logger.logRegistrationFailure(finalSessionId, 'Missing credential or userId', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Missing credential or user ID',
      }, { status: 400 });
    }

    // Get the stored challenge
    const expectedChallenge = db.getChallenge(finalSessionId);
    if (!expectedChallenge) {
      logger.logRegistrationFailure(finalSessionId, 'Challenge not found or expired', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Challenge not found or expired',
      }, { status: 400 });
    }

    // Get the user
    const user = db.getUserById(userId);
    if (!user) {
      logger.logRegistrationFailure(finalSessionId, 'User not found', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'User not found',
      }, { status: 404 });
    }

    const { rpID, origin } = getWebAuthnConfig();

    // Verify the registration response
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });
    } catch (verificationError) {
      const verificationErrorMessage = verificationError instanceof Error ? verificationError.message : 'Unknown verification error';
      logger.logRegistrationFailure(finalSessionId, `Verification error: ${verificationErrorMessage}`, ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: `Registration verification error: ${verificationErrorMessage}`,
      }, { status: 400 });
    }

    if (!verification.verified || !verification.registrationInfo) {
      logger.logRegistrationFailure(finalSessionId, 'Registration verification failed', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'Registration verification failed',
      }, { status: 400 });
    }

    const { 
      credential: regCredential,
      aaguid,
    } = verification.registrationInfo;
    
    const credentialID = regCredential.id;
    const credentialPublicKey = regCredential.publicKey;
    const counter = regCredential.counter;

    // Store the authenticator
    try {
      const authenticator = db.createAuthenticator({
        userId: user.id,
        credentialId: typeof credentialID === 'string' ? Buffer.from(credentialID, 'base64url') : Buffer.from(credentialID),
        publicKey: credentialPublicKey instanceof Uint8Array ? Buffer.from(credentialPublicKey) : Buffer.from(credentialPublicKey),
        counter,
        aaguid: aaguid ? aaguid.toString() : undefined,
      });

      // Update user's last login
      db.updateUser(user.id, {
        lastLoginAt: new Date(),
      });

      // Clean up the challenge
      db.deleteChallenge(finalSessionId);

      logger.logRegistrationSuccess(
        user.id,
        finalSessionId,
        {
          credentialId: typeof credentialID === 'string' ? credentialID : Buffer.from(credentialID).toString('base64url'),
          aaguid: aaguid ? aaguid.toString() : undefined,
        },
        ipAddress,
        userAgent
      );
    } catch (dbError) {
      const dbErrorMessage = dbError instanceof Error ? dbError.message : 'Unknown database error';
      logger.logRegistrationFailure(finalSessionId, `Database error: ${dbErrorMessage}`, ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: `Registration storage error: ${dbErrorMessage}`,
      }, { status: 500 });
    }

    // Clear the session cookie
    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });

    response.cookies.set('webauthn-session', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 0, // Delete the cookie
    });

    return response;

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    logger.error('webauthn_registration_verification_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      error: 'Registration failed',
    }, { status: 500 });
  }
}