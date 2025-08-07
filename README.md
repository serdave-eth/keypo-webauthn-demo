# WebAuthn Passkeys Authentication Demo

A complete Next.js application implementing WebAuthn passkeys authentication with biometric verification, JWT token management, and comprehensive security logging.

## Features

- **WebAuthn Passkeys Authentication**: Secure biometric authentication using device-native capabilities
- **JWT Token Management**: Stateless authentication with JSON Web Tokens
- **Comprehensive Logging**: Detailed audit trail for all authentication events
- **Modern UI**: Responsive design with error handling and loading states
- **TypeScript**: Fully typed for better development experience
- **Security-First**: Follows WebAuthn security best practices

## Technology Stack

- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript
- **WebAuthn**: @simplewebauthn/server and @simplewebauthn/browser
- **Authentication**: JSON Web Tokens (jsonwebtoken)
- **Database**: In-memory storage for demo purposes
- **Styling**: Custom CSS (easily replaceable with Tailwind/other frameworks)

## Getting Started

### Prerequisites

- Node.js 18+ 
- A modern browser with WebAuthn support (Chrome 85+, Firefox 90+, Safari 14+, Edge 90+)
- A device with biometric capabilities (fingerprint, face recognition, etc.)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd keypo-backendauth-demo
```

2. Install dependencies:
```bash
npm install
```

3. Copy the environment file and configure:
```bash
cp .env.example .env.local
```

4. Edit `.env.local` with your configuration:
```env
# WebAuthn Configuration
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_RP_ID=localhost  # Change to your domain in production
WEBAUTHN_ORIGIN=http://localhost:3000  # Change to your URL in production

# JWT Configuration  
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long
JWT_EXPIRATION=1h

# Logging Configuration
LOG_LEVEL=info
```

### Development

Start the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Building for Production

```bash
npm run build
npm start
```

## Usage

### Registration Flow

1. Click "Register with Passkey"
2. Your browser will prompt for biometric authentication
3. Complete the biometric verification (fingerprint, face recognition, etc.)
4. You'll be registered and automatically signed in

### Authentication Flow

1. Click "Sign In with Passkey"
2. Your browser will prompt for biometric authentication
3. Complete the biometric verification
4. You'll be authenticated and receive a JWT token

### Sign Out

Click "Sign Out" to clear your authentication session.

## API Endpoints

### Registration
- `POST /api/auth/register/begin` - Initialize registration ceremony
- `POST /api/auth/register/finish` - Complete registration ceremony

### Authentication
- `POST /api/auth/login/begin` - Initialize authentication ceremony
- `POST /api/auth/login/finish` - Complete authentication ceremony

### Session Management
- `POST /api/auth/logout` - Sign out user
- `GET /api/auth/verify` - Verify JWT token and get user info

## Security Features

- **Biometric Verification Required**: All authentications require device biometrics
- **Origin Validation**: WebAuthn ceremonies validate the origin
- **Challenge-Response**: Cryptographic challenges prevent replay attacks
- **JWT Security**: Tokens are signed and have expiration times
- **Counter Tracking**: Authenticator counters prevent cloning attacks
- **Comprehensive Logging**: All security events are logged with details

## Production Deployment

### Environment Variables

For production, ensure you set:

```env
WEBAUTHN_RP_NAME=Your Production App Name
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_ORIGIN=https://yourdomain.com
JWT_SECRET=very-strong-randomly-generated-secret-key
JWT_EXPIRATION=1h
LOG_LEVEL=warn
```

### Production Checklist

- [ ] **HTTPS Required**: WebAuthn requires HTTPS in production
- [ ] **Domain Configuration**: Set correct RPID and Origin for your domain
- [ ] **Strong JWT Secret**: Use a cryptographically strong secret key
- [ ] **Database**: Replace in-memory storage with persistent database
- [ ] **Rate Limiting**: Implement rate limiting on authentication endpoints
- [ ] **Monitoring**: Set up monitoring and alerting
- [ ] **Backup**: Implement backup strategy for user data
- [ ] **Error Handling**: Ensure error messages don't leak sensitive information

### Deployment Platforms

This application can be deployed to:
- Vercel
- Netlify  
- AWS (Lambda, ECS, EC2)
- Google Cloud Platform
- Azure
- DigitalOcean

### Database Migration

For production, replace the in-memory database with:
- PostgreSQL
- MySQL
- MongoDB
- Firebase Firestore
- Supabase

Update the `lib/db.ts` file to integrate with your chosen database.

## Browser Compatibility

### Supported Browsers
- Chrome 85+ (desktop and mobile)
- Firefox 90+ (desktop and mobile)
- Safari 14+ (desktop and mobile)  
- Edge 90+

### Fallbacks
The application automatically detects WebAuthn support and shows appropriate messages for unsupported browsers.

## Troubleshooting

### Common Issues

**"WebAuthn not supported"**
- Ensure you're using HTTPS in production
- Check browser compatibility
- Verify device has biometric capabilities

**"Registration failed"**
- Check browser console for detailed errors
- Verify environment variables are correct
- Ensure origin matches the current domain

**"Authentication failed"**
- Try registering again if authenticator data is corrupted
- Check server logs for detailed error information
- Verify JWT secret is consistent

### Debug Mode

Set `LOG_LEVEL=debug` in your environment to see detailed logging information.

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## Security

This application is designed for demonstration purposes. For production use:

- Conduct thorough security testing
- Implement proper database security
- Add rate limiting and DDoS protection
- Regular security audits
- Keep dependencies updated

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [SimpleWebAuthn](https://simplewebauthn.dev/) - Excellent WebAuthn library
- [WebAuthn.guide](https://webauthn.guide/) - Great WebAuthn learning resource
- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/) - Official specification