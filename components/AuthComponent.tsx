'use client';

import React, { useState, useEffect } from 'react';
import { webAuthnClient } from '@/lib/webauthn-client';
import type { AuthenticationResult, RegistrationResult } from '@/lib/webauthn-client';

interface User {
  id: string;
  username?: string;
  email?: string;
}

export default function AuthComponent() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' }>({
    text: '',
    type: 'info'
  });
  const [browserSupported, setBrowserSupported] = useState<boolean | null>(null);

  useEffect(() => {
    const isSupported = webAuthnClient.isSupported();
    setBrowserSupported(isSupported);

    if (!isSupported) {
      setMessage({
        text: 'WebAuthn is not supported in this browser. Please use a modern browser with biometric capabilities.',
        type: 'error'
      });
      setIsCheckingAuth(false);
      return;
    }

    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    setIsCheckingAuth(true);
    try {
      const result = await webAuthnClient.verifyAuth();
      if (result.success && result.user) {
        setUser(result.user);
        setMessage({
          text: `Welcome back, ${result.user.username || 'User'}!`,
          type: 'success'
        });
      } else {
        setUser(null);
        setMessage({
          text: 'Please register or sign in with your passkey.',
          type: 'info'
        });
      }
    } catch (error) {
      setUser(null);
      setMessage({
        text: 'Unable to verify authentication status.',
        type: 'error'
      });
    } finally {
      setIsCheckingAuth(false);
    }
  };

  const handleRegister = async () => {
    if (!username.trim()) {
      setMessage({
        text: 'Please enter a username.',
        type: 'error'
      });
      return;
    }

    setIsLoading(true);
    setMessage({ text: 'Starting registration...', type: 'info' });

    try {
      const result: RegistrationResult = await webAuthnClient.register(username.trim());
      
      if (result.success && result.user) {
        setUser(result.user);
        setUsername(''); // Clear the username field
        setMessage({
          text: `Registration successful! Welcome, ${result.user.username || 'User'}!`,
          type: 'success'
        });
      } else {
        setMessage({
          text: result.error || 'Registration failed. Please try again.',
          type: 'error'
        });
      }
    } catch (error) {
      setMessage({
        text: 'Registration failed due to an unexpected error.',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async () => {
    setIsLoading(true);
    setMessage({ text: 'Starting authentication...', type: 'info' });

    try {
      const result: AuthenticationResult = await webAuthnClient.authenticate();
      
      if (result.success && result.user) {
        setUser(result.user);
        setMessage({
          text: `Login successful! Welcome back, ${result.user.username || 'User'}!`,
          type: 'success'
        });
      } else {
        setMessage({
          text: result.error || 'Authentication failed. Please try again.',
          type: 'error'
        });
      }
    } catch (error) {
      setMessage({
        text: 'Authentication failed due to an unexpected error.',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    setIsLoading(true);
    setMessage({ text: 'Signing out...', type: 'info' });

    try {
      const result = await webAuthnClient.signOut();
      
      if (result.success) {
        setUser(null);
        setMessage({
          text: 'Successfully signed out.',
          type: 'success'
        });
      } else {
        setMessage({
          text: result.error || 'Sign out failed.',
          type: 'error'
        });
      }
    } catch (error) {
      setMessage({
        text: 'Sign out failed due to an unexpected error.',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (browserSupported === null || isCheckingAuth) {
    return (
      <div className="container">
        <div className="text-center">
          <div className="spinner w-12 h-12 mb-4" style={{ margin: '0 auto' }}></div>
          <p className="text-gray-600">Initializing...</p>
        </div>
      </div>
    );
  }

  if (!browserSupported) {
    return (
      <div className="container">
        <div className="card">
          <div className="text-center">
            <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>⚠️</div>
            <h1 className="text-2xl font-bold text-gray-900 mb-4">Browser Not Supported</h1>
            <p className="text-gray-600 mb-4">
              WebAuthn passkeys are not supported in this browser. Please use a modern browser that supports biometric authentication:
            </p>
            <ul style={{ textAlign: 'left', fontSize: '0.875rem', color: '#4b5563' }}>
              <li>• Chrome 85+ (desktop and mobile)</li>
              <li>• Firefox 90+ (desktop and mobile)</li>
              <li>• Safari 14+ (desktop and mobile)</li>
              <li>• Edge 90+</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card">
        <div className="text-center mb-6">
          <div className="text-4xl mb-2">🔐</div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">WebAuthn Passkeys Demo</h1>
          <p className="text-gray-600">
            Secure authentication using biometric passkeys
          </p>
        </div>

        {message.text && (
          <div className={`message ${
            message.type === 'success' ? 'message-success' :
            message.type === 'error' ? 'message-error' :
            'message-info'
          }`}>
            {message.text}
          </div>
        )}

        {user ? (
          <div className="space-y-4">
            <div className="bg-gray-50 p-4 rounded-md">
              <h2 className="font-semibold text-gray-900 mb-2">Authenticated User</h2>
              <div className="text-sm space-y-1">
                <p><span className="font-medium">Username:</span> {user.username || 'N/A'}</p>
                <p><span className="font-medium">Email:</span> {user.email || 'N/A'}</p>
                <p><span className="font-medium">ID:</span> {user.id.slice(0, 8)}...</p>
              </div>
            </div>
            
            <button
              onClick={handleLogout}
              disabled={isLoading}
              className="button button-red"
            >
              {isLoading ? (
                <>
                  <div className="spinner mr-2"></div>
                  Signing Out...
                </>
              ) : (
                'Sign Out'
              )}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                Username
              </label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                disabled={isLoading}
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                maxLength={50}
              />
            </div>
            
            <button
              onClick={handleRegister}
              disabled={isLoading || !username.trim()}
              className="button button-blue"
            >
              {isLoading ? (
                <>
                  <div className="spinner mr-2"></div>
                  Registering...
                </>
              ) : (
                <>
                  <span className="mr-2">👆</span>
                  Register with Passkey
                </>
              )}
            </button>
            
            <div className="divider-container">
              <div className="divider"></div>
              <span className="divider-label">or</span>
            </div>
            
            <button
              onClick={handleLogin}
              disabled={isLoading}
              className="button button-green"
            >
              {isLoading ? (
                <>
                  <div className="spinner mr-2"></div>
                  Signing In...
                </>
              ) : (
                <>
                  <span className="mr-2">🔑</span>
                  Sign In with Passkey
                </>
              )}
            </button>
          </div>
        )}

        <div className="mt-6 pt-4 border-t border-gray-200">
          <p className="text-xs text-gray-500 text-center">
            This demo uses WebAuthn with biometric authentication. Your biometric data never leaves your device.
          </p>
        </div>
      </div>
    </div>
  );
}