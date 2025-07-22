# OAuth Identity Provider Server

A FastAPI-based OAuth 2.0 Identity Provider with SQLite backend for securing MCP servers and other applications.

## Features

- OAuth 2.0 Authorization Code Flow
- User authentication with bcrypt password hashing
- SQLite database (configurable to PostgreSQL/MySQL)
- Environment-based configuration
- CORS support
- OAuth discovery endpoint

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

### OAuth 2.0 Endpoints
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/login` - User login handler
- `POST /oauth/token` - Token exchange
- `GET /oauth/userinfo` - User information
- `GET /.well-known/oauth-authorization-server` - OAuth discovery

### Management Endpoints (Development Only)
- `POST /register` - User registration
- `POST /register_client` - OAuth client registration

## Usage Example

### 1. Register a User
```bash
curl -X POST "${BASE_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass&email=test@example.com"
```

### 2. Register an OAuth Client
```bash
curl -X POST "${BASE_URL}/register_client" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=MCP Server&redirect_uri=http://localhost:3000/callback"
```

### 3. OAuth Flow
1. Direct user to: `${BASE_URL}/oauth/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={STATE}`
2. User logs in and is redirected with authorization code
3. Exchange code for token:
```bash
curl -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code={CODE}&redirect_uri={REDIRECT_URI}&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
```

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
- Use HTTPS in production
- Configure CORS origins appropriately
- Use a strong secret key
- Consider rate limiting
- Use a proper database (PostgreSQL/MySQL) for production
- Implement proper logging and monitoring

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