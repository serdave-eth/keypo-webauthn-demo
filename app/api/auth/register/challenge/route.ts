import { NextRequest, NextResponse } from 'next/server';
import { generateRegistrationOptions, getWebAuthnConfig } from '@/lib/webauthn';
import { db } from '@/lib/db';
import { logger } from '@/lib/logger';

export async function POST(request: NextRequest) {
  try {
    const sessionId = crypto.randomUUID();
    const ipAddress = request.headers.get('x-forwarded-for') || 
                      request.headers.get('x-real-ip') || 
                      'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    logger.logRegistrationAttempt(sessionId, ipAddress, userAgent);

    // Parse the request body to get the username
    const body = await request.json().catch(() => ({}));
    const { username: requestedUsername } = body;

    const { rpName, rpID, origin } = getWebAuthnConfig();
    
    // Generate a unique user ID for this registration
    const userId = crypto.randomUUID();
    const userName = requestedUsername?.trim() || `user-${Date.now()}`;
    
    // Create a temporary user record
    const user = db.createUser({
      email: `${userName}@demo.com`,
      username: userName,
    });

    // Get existing authenticators for this user (should be empty for new user)
    const userAuthenticators = db.getAuthenticatorsByUserId(user.id);
    
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.username || user.id,
      userID: Buffer.from(user.id, 'utf-8'),
      userDisplayName: user.username || `User ${user.id.slice(0, 8)}`,
      attestationType: 'none',
      excludeCredentials: userAuthenticators.map(authenticator => ({
        id: Buffer.from(authenticator.credentialId).toString('base64url'),
        type: 'public-key',
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform',
      },
      timeout: 60000, // 60 seconds timeout
    });

    // Store the challenge for later verification
    db.saveChallenge(sessionId, options.challenge);

    logger.info('webauthn_registration_challenge_generated', {
      userId: user.id,
      sessionId,
      ipAddress,
      userAgent,
      metadata: {
        rpID,
        userName: user.username,
      }
    });

    const response = NextResponse.json({
      success: true,
      options,
      sessionId,
      userId: user.id,
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
    
    logger.error('webauthn_registration_challenge_error', {
      error: errorMessage,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    return NextResponse.json({
      success: false,
      error: 'Failed to generate registration options',
    }, { status: 500 });
  }
}