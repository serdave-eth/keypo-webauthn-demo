import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} from '@simplewebauthn/browser';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/browser';

interface RegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{
    alg: number;
    type: 'public-key';
  }>;
  authenticatorSelection: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'discouraged' | 'preferred' | 'required';
    userVerification?: 'discouraged' | 'preferred' | 'required';
  };
  attestation?: 'none' | 'indirect' | 'direct' | 'enterprise';
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
  }>;
}

interface AuthenticationOptions {
  challenge: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
  }>;
  rpId?: string;
  userVerification?: 'discouraged' | 'preferred' | 'required';
}

export interface RegistrationChallengeResponse {
  success: boolean;
  options?: RegistrationOptions;
  sessionId?: string;
  userId?: string;
  error?: string;
}

export interface AuthenticationChallengeResponse {
  success: boolean;
  options?: AuthenticationOptions;
  sessionId?: string;
  error?: string;
}

export interface AuthenticationResult {
  success: boolean;
  user?: {
    id: string;
    username?: string;
    email?: string;
  };
  token?: string;
  error?: string;
}

export interface RegistrationResult {
  success: boolean;
  user?: {
    id: string;
    username?: string;
    email?: string;
  };
  error?: string;
}

export class WebAuthnClient {
  private static instance: WebAuthnClient;

  static getInstance(): WebAuthnClient {
    if (!WebAuthnClient.instance) {
      WebAuthnClient.instance = new WebAuthnClient();
    }
    return WebAuthnClient.instance;
  }

  /**
   * Check if WebAuthn is supported in the current browser
   */
  isSupported(): boolean {
    return browserSupportsWebAuthn();
  }

  /**
   * Register a new passkey
   */
  async register(username?: string): Promise<RegistrationResult> {
    try {
      if (!this.isSupported()) {
        return {
          success: false,
          error: 'WebAuthn is not supported in this browser',
        };
      }

      // Step 1: Get registration challenge
      const challengeResponse = await fetch('/api/auth/register/challenge', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username || undefined,
        }),
      });

      if (!challengeResponse.ok) {
        const error = await challengeResponse.text();
        return {
          success: false,
          error: `Failed to get registration challenge: ${error}`,
        };
      }

      const challengeData: RegistrationChallengeResponse = await challengeResponse.json();

      if (!challengeData.success || !challengeData.options) {
        return {
          success: false,
          error: challengeData.error || 'Failed to get registration options',
        };
      }

      // Step 2: Start WebAuthn registration ceremony
      let registrationResponse: RegistrationResponseJSON;
      
      try {
        registrationResponse = await startRegistration({ optionsJSON: challengeData.options });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        return {
          success: false,
          error: `Registration ceremony failed: ${errorMessage}`,
        };
      }

      // Step 3: Verify registration
      const verificationResponse = await fetch('/api/auth/register/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credential: registrationResponse,
          userId: challengeData.userId,
          sessionId: challengeData.sessionId,
        }),
      });

      if (!verificationResponse.ok) {
        const error = await verificationResponse.text();
        return {
          success: false,
          error: `Failed to verify registration: ${error}`,
        };
      }

      const verificationResult: RegistrationResult = await verificationResponse.json();
      return verificationResult;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        error: `Registration failed: ${errorMessage}`,
      };
    }
  }

  /**
   * Authenticate with an existing passkey
   */
  async authenticate(): Promise<AuthenticationResult> {
    try {
      if (!this.isSupported()) {
        return {
          success: false,
          error: 'WebAuthn is not supported in this browser',
        };
      }

      // Step 1: Get authentication challenge
      const challengeResponse = await fetch('/api/auth/login/challenge', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!challengeResponse.ok) {
        const error = await challengeResponse.text();
        return {
          success: false,
          error: `Failed to get authentication challenge: ${error}`,
        };
      }

      const challengeData: AuthenticationChallengeResponse = await challengeResponse.json();

      if (!challengeData.success || !challengeData.options) {
        return {
          success: false,
          error: challengeData.error || 'Failed to get authentication options',
        };
      }

      // Step 2: Start WebAuthn authentication ceremony
      let authenticationResponse: AuthenticationResponseJSON;
      
      try {
        authenticationResponse = await startAuthentication({ optionsJSON: challengeData.options });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        return {
          success: false,
          error: `Authentication ceremony failed: ${errorMessage}`,
        };
      }

      // Step 3: Verify authentication
      const verificationResponse = await fetch('/api/auth/login/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credential: authenticationResponse,
          sessionId: challengeData.sessionId,
        }),
      });

      if (!verificationResponse.ok) {
        const error = await verificationResponse.text();
        return {
          success: false,
          error: `Failed to verify authentication: ${error}`,
        };
      }

      const verificationResult: AuthenticationResult = await verificationResponse.json();
      return verificationResult;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        error: `Authentication failed: ${errorMessage}`,
      };
    }
  }

  /**
   * Sign out the current user
   */
  async signOut(): Promise<{ success: boolean; error?: string }> {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const error = await response.text();
        return {
          success: false,
          error: `Failed to sign out: ${error}`,
        };
      }

      const data = await response.json();
      return data;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        error: `Sign out failed: ${errorMessage}`,
      };
    }
  }

  /**
   * Verify the current authentication status
   */
  async verifyAuth(): Promise<AuthenticationResult> {
    try {
      const response = await fetch('/api/auth/verify', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        return {
          success: false,
          error: 'Not authenticated',
        };
      }

      const data = await response.json();
      
      if (data.authenticated) {
        return {
          success: true,
          user: data.user,
        };
      } else {
        return {
          success: false,
          error: data.error || 'Not authenticated',
        };
      }

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        error: `Auth verification failed: ${errorMessage}`,
      };
    }
  }
}

export const webAuthnClient = WebAuthnClient.getInstance();