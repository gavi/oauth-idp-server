# OAuth Identity Provider Server

A FastAPI-based OAuth 2.0 Identity Provider with SQLite backend for securing MCP servers and other applications.

## Features

- **RFC-Compliant OAuth 2.0 Server** (RFC 6749)
- **Dynamic Client Registration** (RFC 7591) - Zapier compatible
- **Token Revocation** (RFC 7009)
- **OAuth Server Metadata** (RFC 8414)
- **MCP Third-Party Authorization Flow** (2025-03-26 specification)
- Third-party provider delegation (Google, GitHub, Auth0, etc.)
- Secure session binding between third-party and MCP tokens
- Scope-based access control (profile, email)
- User authentication with bcrypt password hashing
- SQLite database (configurable to PostgreSQL/MySQL)
- Environment-based configuration
- CORS support
- JWT-based tokens with RSA signing

## Quick Start

### Installation

```bash
# Clone or create the project
# Copy the files: main.py, pyproject.toml, .env.example

# Install dependencies
uv sync

# Create environment file
cp .env.example .env
# Edit .env with your configuration
```

### Configuration

Create a `.env` file based on `.env.example`:

```bash
BASE_URL=https://your-domain.com
SECRET_KEY=your-generated-secret-key
DATABASE_URL=sqlite:///./oauth_idp.db
CORS_ORIGINS=https://your-frontend.com,https://your-api.com
```

Generate a secure secret key:
```python
import secrets
print(secrets.token_urlsafe(32))
```

### Running

```bash
# Development
uv run python main.py

# Or with uvicorn directly
uv run uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Production
uv run uvicorn main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### OAuth 2.0 Endpoints (RFC Compliant)
- `GET /oauth/authorize` - Authorization endpoint (supports third-party delegation)
- `POST /oauth/login` - User login handler
- `POST /oauth/token` - Token exchange
- `POST /register` - Dynamic client registration (RFC 7591)
- `POST /revoke` - Token revocation (RFC 7009)
- `GET /oauth/userinfo` - User information with scope-based filtering
- `GET /.well-known/oauth-authorization-server` - OAuth discovery (RFC 8414)
- `GET /oauth/third-party/callback/{session_id}` - Third-party authorization callback

### Management Endpoints (Development Only)
- `POST /register` - User registration
- `POST /register_client` - Legacy OAuth client registration (use `/register` instead)

### Third-Party Provider Management
- `POST /admin/register_provider` - Register third-party authorization provider
- `GET /admin/providers` - List active third-party providers
- `POST /admin/providers/{id}/deactivate` - Deactivate third-party provider

## Usage Example

### 1. Register a User
```bash
curl -X POST "${BASE_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass&email=test@example.com"
```

### 2. Register an OAuth Client (RFC 7591 Compliant)
```bash
curl -X POST "${BASE_URL}/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "MCP Server",
    "redirect_uris": ["http://localhost:3000/callback", "http://localhost:3000/oauth/callback"]
  }'
```

Response:
```json
{
  "client_id": "abc123...",
  "client_secret": "def456...",
  "client_name": "MCP Server",
  "redirect_uris": ["http://localhost:3000/callback", "http://localhost:3000/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_post",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0
}
```

### 3. Register a Third-Party Provider (Optional)
```bash
curl -X POST "${BASE_URL}/admin/register_provider" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=google&client_id=your-google-client-id&client_secret=your-google-client-secret&authorization_endpoint=https://accounts.google.com/o/oauth2/auth&token_endpoint=https://oauth2.googleapis.com/token&userinfo_endpoint=https://www.googleapis.com/oauth2/v2/userinfo&scope=openid profile email"
```

### 4. OAuth Flow

#### Standard OAuth Flow
1. Direct user to: `${BASE_URL}/oauth/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={STATE}`
2. User logs in and is redirected with authorization code
3. Exchange code for token:
```bash
curl -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code={CODE}&redirect_uri={REDIRECT_URI}&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
```

#### Third-Party Authorization Flow (MCP Extension)
1. Direct user to: `${BASE_URL}/oauth/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={STATE}&provider=google`
2. User is redirected to Google for authentication
3. Google redirects back to MCP server with authorization code
4. MCP server processes third-party authorization and generates MCP tokens
5. User is redirected to your application with MCP authorization code
6. Exchange MCP code for MCP token (same as standard flow)

## Deployment

### Environment Variables for Production

```bash
BASE_URL=https://your-domain.com
SECRET_KEY=your-secure-secret-key
DATABASE_URL=postgresql://user:password@localhost/oauth_idp
CORS_ORIGINS=https://your-frontend.com
HOST=0.0.0.0
PORT=8000
```

### Docker Example

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY . .

# Install dependencies
RUN uv sync --frozen

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Security Considerations

- Remove `/register` and `/register_client` endpoints in production
- Secure `/admin/*` endpoints with proper authentication in production
- Use HTTPS in production
- Configure CORS origins appropriately
- Use a strong secret key
- Consider rate limiting
- Use a proper database (PostgreSQL/MySQL) for production
- Implement proper logging and monitoring
- Validate third-party provider redirect URIs
- Store third-party client secrets securely
- Implement session timeout handling
- Monitor third-party token expiration and renewal

## Database Support

The server supports multiple databases through SQLAlchemy:

- **SQLite** (default): `sqlite:///./oauth_idp.db`
- **PostgreSQL**: `postgresql://user:password@localhost/dbname`
- **MySQL**: `mysql://user:password@localhost/dbname`

## MCP Server Integration

Configure your MCP servers to use this IdP:

- Authorization Endpoint: `${BASE_URL}/oauth/authorize`
- Token Endpoint: `${BASE_URL}/oauth/token`
- User Info Endpoint: `${BASE_URL}/oauth/userinfo`
- Discovery Endpoint: `${BASE_URL}/.well-known/oauth-authorization-server`

### Third-Party Authorization Flow

The server implements the MCP Third-Party Authorization Flow specification (2025-03-26):

1. **Session Binding**: MCP tokens are securely bound to third-party authorization sessions
2. **Token Validation**: Third-party token status is validated before honoring MCP tokens
3. **Lifecycle Management**: Automatic cleanup of expired sessions and tokens
4. **Provider Discovery**: Available third-party providers are advertised in OAuth metadata

#### Discovery Response Example (Zapier Compatible)
```json
{
  "issuer": "https://your-idp.com",
  "authorization_endpoint": "https://your-idp.com/oauth/authorize",
  "token_endpoint": "https://your-idp.com/oauth/token",
  "registration_endpoint": "https://your-idp.com/register",
  "revocation_endpoint": "https://your-idp.com/revoke",
  "userinfo_endpoint": "https://your-idp.com/oauth/userinfo",
  "jwks_uri": "https://your-idp.com/.well-known/jwks.json",
  "scopes_supported": ["profile", "email"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"],
  "third_party_providers_supported": ["google", "github"],
  "third_party_authorization_endpoint": "https://your-idp.com/oauth/authorize?provider={provider_name}",
  "mcp_third_party_authorization_flow": "2025-03-26"
}
```

#### Supported Third-Party Providers
- Google OAuth 2.0
- GitHub OAuth 2.0
- Auth0
- Any OpenID Connect compliant provider

To use third-party authorization, add the `provider` parameter to your authorization URL:
```
https://your-idp.com/oauth/authorize?response_type=code&client_id=YOUR_CLIENT&redirect_uri=YOUR_CALLBACK&provider=google
```