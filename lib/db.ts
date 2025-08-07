import { User, Authenticator } from '@/types/auth';

class InMemoryDatabase {
  private users: Map<string, User> = new Map();
  private authenticators: Map<string, Authenticator> = new Map();
  private userByCredentialId: Map<string, string> = new Map();
  private currentChallenge: Map<string, string> = new Map();

  // User operations
  createUser(user: Omit<User, 'id' | 'createdAt'>): User {
    const id = this.generateId();
    const newUser: User = {
      id,
      ...user,
      createdAt: new Date(),
    };
    this.users.set(id, newUser);
    return newUser;
  }

  getUserById(id: string): User | null {
    return this.users.get(id) || null;
  }

  getUserByEmail(email: string): User | null {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }

  updateUser(id: string, updates: Partial<User>): User | null {
    const user = this.users.get(id);
    if (!user) return null;
    
    const updatedUser = { ...user, ...updates };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  // Authenticator operations
  createAuthenticator(authenticator: Omit<Authenticator, 'id' | 'createdAt'>): Authenticator {
    const id = this.generateId();
    const newAuthenticator: Authenticator = {
      id,
      ...authenticator,
      createdAt: new Date(),
    };
    
    this.authenticators.set(id, newAuthenticator);
    this.userByCredentialId.set(authenticator.credentialId.toString('base64'), authenticator.userId);
    return newAuthenticator;
  }

  getAuthenticatorById(id: string): Authenticator | null {
    return this.authenticators.get(id) || null;
  }

  getAuthenticatorByCredentialId(credentialId: Buffer): Authenticator | null {
    const credentialIdStr = credentialId.toString('base64');
    const userId = this.userByCredentialId.get(credentialIdStr);
    
    if (!userId) return null;

    for (const authenticator of this.authenticators.values()) {
      if (authenticator.userId === userId && 
          authenticator.credentialId.toString('base64') === credentialIdStr) {
        return authenticator;
      }
    }
    return null;
  }

  getAuthenticatorsByUserId(userId: string): Authenticator[] {
    const authenticators: Authenticator[] = [];
    for (const authenticator of this.authenticators.values()) {
      if (authenticator.userId === userId) {
        authenticators.push(authenticator);
      }
    }
    return authenticators;
  }

  updateAuthenticator(id: string, updates: Partial<Authenticator>): Authenticator | null {
    const authenticator = this.authenticators.get(id);
    if (!authenticator) return null;
    
    const updatedAuthenticator = { ...authenticator, ...updates };
    this.authenticators.set(id, updatedAuthenticator);
    return updatedAuthenticator;
  }

  // Challenge management for WebAuthn flows
  saveChallenge(sessionId: string, challenge: string): void {
    this.currentChallenge.set(sessionId, challenge);
  }

  getChallenge(sessionId: string): string | null {
    return this.currentChallenge.get(sessionId) || null;
  }

  deleteChallenge(sessionId: string): void {
    this.currentChallenge.delete(sessionId);
  }

  // Utility methods
  private generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }

  // Development helpers
  getAllUsers(): User[] {
    return Array.from(this.users.values());
  }

  getAllAuthenticators(): Authenticator[] {
    return Array.from(this.authenticators.values());
  }

  clear(): void {
    this.users.clear();
    this.authenticators.clear();
    this.userByCredentialId.clear();
    this.currentChallenge.clear();
  }
}

// Create singleton instance
export const db = new InMemoryDatabase();