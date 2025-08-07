import { NextRequest, NextResponse } from 'next/server';
import { generateAuthenticationOptions, getWebAuthnConfig } from '@/lib/webauthn';
import { db } from '@/lib/db';
import { logger } from '@/lib/logger';

export async function POST(request: NextRequest) {
  try {
    const sessionId = crypto.randomUUID();
    const ipAddress = request.headers.get('x-forwarded-for') || 
                      request.headers.get('x-real-ip') || 
                      'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    logger.logAuthenticationAttempt(sessionId, ipAddress, userAgent);

    const { rpID } = getWebAuthnConfig();
    
    // Get all registered authenticators to allow any user to authenticate
    const allAuthenticators = db.getAllAuthenticators();
    
    if (allAuthenticators.length === 0) {
      logger.logAuthenticationFailure(sessionId, 'No authenticators registered', ipAddress, userAgent);
      return NextResponse.json({
        success: false,
        error: 'No registered authenticators found. Please register first.',
      }, { status: 400 });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: allAuthenticators.map(authenticator => ({
        id: Buffer.from(authenticator.credentialId).toString('base64url'),
        type: 'public-key' as const,
        transports: ['internal', 'usb', 'ble', 'nfc'],
      })),
      userVerification: 'preferred',
      timeout: 60000, // 60 seconds timeout
    });

    // Store the challenge for later verification
    db.saveChallenge(sessionId, options.challenge);

    logger.info('webauthn_authentication_challenge_generated', {
      sessionId,
      ipAddress,
      userAgent,
      metadata: {
        rpID,
        credentialCount: allAuthenticators.length,
      }
    });

    const response = NextResponse.json({
      success: true,
      options,
      sessionId,
    });

    // Set session cookie
    response.cookies.set('webauthn-session', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 300, // 5 minutes
    });

    return response;

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    logger.error('webauthn_authentication_challenge_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      error: 'Failed to generate authentication options',
    }, { status: 500 });
  }
}