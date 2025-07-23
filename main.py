from fastapi import FastAPI, HTTPException, Depends, status, Form, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import secrets
import hashlib
import os
from typing import Optional
import urllib.parse
import base64
import json
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
import logging
import time
import uuid
load_dotenv()

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)

logger = logging.getLogger("oauth_idp")

# Environment variables
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./oauth_idp.db")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# RSA key pair for JWT signing
def load_or_generate_keys():
    private_key_path = os.getenv("PRIVATE_KEY_PATH", "jwt_private_key.pem")
    public_key_path = os.getenv("PUBLIC_KEY_PATH", "jwt_public_key.pem")
    
    # Try to load existing keys
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        try:
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            logger.info("Loaded existing RSA keys")
            return private_key, public_key
        except Exception as e:
            logger.warning(f"Error loading keys: {e}, generating new ones")
    
    # Generate new keys if loading failed or files don't exist
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Save keys if in development mode
    if os.getenv("SAVE_KEYS", "true").lower() == "true":
        try:
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logger.info(f"Generated and saved new RSA keys to {private_key_path} and {public_key_path}")
        except Exception as e:
            logger.error(f"Could not save keys: {e}")
    else:
        logger.info("Generated new RSA keys (not saved)")
    
    return private_key, public_key

private_key, public_key = load_or_generate_keys()

# Serialize keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Key ID for JWKS
KEY_ID = "main-key-" + secrets.token_hex(8)

logger.info(f"Server starting on port {PORT}")
logger.info(f"JWT Key ID: {KEY_ID}")
logger.info(f"Base URL: {BASE_URL}")
logger.info(f"Database URL: {DATABASE_URL}")
logger.info(f"Log level: {LOG_LEVEL}")
# Database setup
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
ALGORITHM = "RS256"  # Changed to RSA
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
AUTHORIZATION_CODE_EXPIRE_MINUTES = int(os.getenv("AUTHORIZATION_CODE_EXPIRE_MINUTES", "10"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="OAuth IdP Server", version="1.0.0")

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Generate unique request ID
    request_id = str(uuid.uuid4())[:8]
    
    # Log request details
    start_time = time.time()
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Get request body for POST requests (be careful with sensitive data)
    body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            # Read body but restore it for the actual handler
            body_bytes = await request.body()
            
            # Only log form data, not raw body for security
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                body_str = body_bytes.decode("utf-8")
                # Hide sensitive fields like passwords and secrets
                body_parts = []
                for part in body_str.split("&"):
                    if "=" in part:
                        key, value = part.split("=", 1)
                        if any(sensitive in key.lower() for sensitive in ["password", "secret", "token"]):
                            body_parts.append(f"{key}=***REDACTED***")
                        else:
                            body_parts.append(part)
                    else:
                        body_parts.append(part)
                body = "&".join(body_parts)
            elif request.headers.get("content-type", "").startswith("application/json"):
                try:
                    json_body = json.loads(body_bytes.decode("utf-8"))
                    # Redact sensitive fields
                    for key in list(json_body.keys()):
                        if any(sensitive in key.lower() for sensitive in ["password", "secret", "token"]):
                            json_body[key] = "***REDACTED***"
                    body = json.dumps(json_body)
                except:
                    body = "***INVALID_JSON***"
            
            # Recreate request with body for the handler
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            
            request._receive = receive
        except Exception as e:
            logger.debug(f"Could not read request body: {e}")
    
    logger.info(f"[{request_id}] {request.method} {request.url.path} - Client: {client_ip} - UA: {user_agent[:100]}")
    if request.url.query:
        logger.info(f"[{request_id}] Query params: {request.url.query}")
    if body:
        logger.info(f"[{request_id}] Request body: {body}")
    
    # Process request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        logger.info(f"[{request_id}] Response: {response.status_code} - Time: {process_time:.3f}s")
        
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"[{request_id}] Request failed: {str(e)} - Time: {process_time:.3f}s")
        raise

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, unique=True, index=True)
    client_secret = Column(String)
    redirect_uri = Column(String)
    name = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    client_id = Column(String)
    user_id = Column(Integer)
    redirect_uri = Column(String)
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)

class ThirdPartyProvider(Base):
    __tablename__ = "third_party_providers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    client_id = Column(String)
    client_secret = Column(String)
    authorization_endpoint = Column(String)
    token_endpoint = Column(String)
    userinfo_endpoint = Column(String)
    scope = Column(String, default="openid profile email")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ThirdPartySession(Base):
    __tablename__ = "third_party_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    provider_id = Column(Integer)
    mcp_client_id = Column(String)
    third_party_access_token = Column(Text)
    third_party_refresh_token = Column(Text, nullable=True)
    third_party_token_expires_at = Column(DateTime, nullable=True)
    third_party_user_id = Column(String)
    mcp_access_token = Column(Text, nullable=True)
    state = Column(String, nullable=True)
    original_redirect_uri = Column(String)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, scope: str = "profile email"):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": BASE_URL,
        "kid": KEY_ID,
        "scope": scope
    })
    encoded_jwt = jwt.encode(to_encode, private_pem, algorithm=ALGORITHM)
    return encoded_jwt

def generate_authorization_code():
    return secrets.token_urlsafe(32)

# User management functions
def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def authenticate_user(db: Session, username: str, password: str):
    logger.info(f"Authentication attempt for user: {username}")
    user = get_user(db, username)
    if not user:
        logger.warning(f"Authentication failed: user {username} not found")
        return False
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Authentication failed: invalid password for user {username}")
        return False
    logger.info(f"Authentication successful for user: {username}")
    return user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, public_pem, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        
        if username is None:
            raise credentials_exception
        
        # Handle third-party bound tokens
        if token_type == "third_party_bound":
            session_id = payload.get("session_id")
            if not session_id:
                raise credentials_exception
            
            session = get_third_party_session(db, session_id)
            if not session or not validate_third_party_token_status(db, session):
                raise credentials_exception
            
            # Return a user-like object for third-party users
            class ThirdPartyUser:
                def __init__(self, session, payload):
                    self.id = payload.get("user_id")
                    self.username = username
                    self.email = f"{payload.get('user_id')}@{payload.get('provider')}"
                    self.provider = payload.get("provider")
                    self.session_id = session_id
                    self.is_third_party = True
            
            return ThirdPartyUser(session, payload)
        
        # Handle standard users
        user = get_user(db, username=username)
        if user is None:
            raise credentials_exception
        user.is_third_party = False
        return user
        
    except JWTError:
        raise credentials_exception

# OAuth Client functions
def get_oauth_client(db: Session, client_id: str):
    return db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

def verify_client_secret(db: Session, client_id: str, client_secret: str):
    client = get_oauth_client(db, client_id)
    if not client:
        return False
    return hashlib.sha256(client_secret.encode()).hexdigest() == client.client_secret

# Third-party provider functions
def get_third_party_provider(db: Session, provider_id: int):
    return db.query(ThirdPartyProvider).filter(
        ThirdPartyProvider.id == provider_id,
        ThirdPartyProvider.is_active == True
    ).first()

def get_third_party_provider_by_name(db: Session, name: str):
    return db.query(ThirdPartyProvider).filter(
        ThirdPartyProvider.name == name,
        ThirdPartyProvider.is_active == True
    ).first()

def create_third_party_session(db: Session, provider_id: int, client_id: str, redirect_uri: str, state: str = None):
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)  # 1 hour session timeout
    
    session = ThirdPartySession(
        session_id=session_id,
        provider_id=provider_id,
        mcp_client_id=client_id,
        original_redirect_uri=redirect_uri,
        state=state,
        expires_at=expires_at
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session

def get_third_party_session(db: Session, session_id: str):
    return db.query(ThirdPartySession).filter(
        ThirdPartySession.session_id == session_id,
        ThirdPartySession.is_active == True,
        ThirdPartySession.expires_at > datetime.utcnow()
    ).first()

async def exchange_third_party_code(provider: ThirdPartyProvider, code: str, redirect_uri: str):
    """Exchange third-party authorization code for tokens"""
    async with httpx.AsyncClient() as client:
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret
        }
        
        response = await client.post(provider.token_endpoint, data=token_data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to exchange authorization code")
        
        return response.json()

async def get_third_party_user_info(provider: ThirdPartyProvider, access_token: str):
    """Get user info from third-party provider"""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await client.get(provider.userinfo_endpoint, headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        return response.json()

def validate_third_party_token_status(db: Session, session: ThirdPartySession):
    """Validate that third-party token is still valid"""
    if not session.is_active:
        return False
    
    if session.third_party_token_expires_at and session.third_party_token_expires_at < datetime.utcnow():
        # Mark session as inactive if token expired
        session.is_active = False
        db.commit()
        return False
    
    return True

# API Endpoints

# User registration (for testing - remove in production)
@app.post("/admin/register")
def register(username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    logger.info(f"User registration attempt for username: {username}, email: {email}")
    
    # Check if user exists
    if get_user(db, username):
        logger.warning(f"Registration failed: username {username} already exists")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Create new user
    hashed_password = get_password_hash(password)
    db_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    logger.info(f"User registration successful for username: {username}")
    return {"message": "User created successfully"}

# OAuth 2.0 Dynamic Client Registration (RFC 7591)
@app.post("/register")
async def register_client(request: Request, db: Session = Depends(get_db)):
    try:
        # Parse JSON body for dynamic client registration
        body = None
        content_type = request.headers.get("content-type", "")
        
        if "application/json" in content_type:
            body = await request.json()
        else:
            # Fallback to form data for backward compatibility
            form = await request.form()
            redirect_uris = form.get("redirect_uris", "").split(",")
            client_name = form.get("client_name", "")
            body = {
                "redirect_uris": [uri.strip() for uri in redirect_uris if uri.strip()],
                "client_name": client_name
            }
    except:
        raise HTTPException(status_code=400, detail="Invalid request body")
    
    # Validate required fields
    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uris is required")
    
    client_name = body.get("client_name", "Unnamed Client")
    
    # Generate client credentials
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    
    # Use first redirect URI as primary
    primary_redirect_uri = redirect_uris[0]
    
    db_client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret_hash,
        redirect_uri=primary_redirect_uri,
        name=client_name
    )
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    
    # Return RFC 7591 compliant response
    response = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "client_id_issued_at": int(datetime.utcnow().timestamp()),
        "client_secret_expires_at": 0  # Never expires
    }
    
    return response

# Legacy client registration (for backward compatibility)
@app.post("/register_client")
def register_client_legacy(name: str = Form(...), redirect_uri: str = Form(...), db: Session = Depends(get_db)):
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    
    db_client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret_hash,
        redirect_uri=redirect_uri,
        name=name
    )
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri
    }

# Third-party provider registration (admin endpoint)
@app.post("/admin/register_provider")
def register_third_party_provider(
    name: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    authorization_endpoint: str = Form(...),
    token_endpoint: str = Form(...),
    userinfo_endpoint: str = Form(...),
    scope: str = Form("openid profile email"),
    db: Session = Depends(get_db)
):
    # Check if provider already exists
    existing = get_third_party_provider_by_name(db, name)
    if existing:
        raise HTTPException(status_code=400, detail="Provider already exists")
    
    provider = ThirdPartyProvider(
        name=name,
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        userinfo_endpoint=userinfo_endpoint,
        scope=scope
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    
    return {
        "id": provider.id,
        "name": provider.name,
        "message": "Third-party provider registered successfully"
    }

# List third-party providers
@app.get("/admin/providers")
def list_third_party_providers(db: Session = Depends(get_db)):
    providers = db.query(ThirdPartyProvider).filter(ThirdPartyProvider.is_active == True).all()
    return {
        "providers": [
            {
                "id": provider.id,
                "name": provider.name,
                "authorization_endpoint": provider.authorization_endpoint,
                "scope": provider.scope,
                "created_at": provider.created_at.isoformat()
            }
            for provider in providers
        ]
    }

# Deactivate third-party provider
@app.post("/admin/providers/{provider_id}/deactivate")
def deactivate_third_party_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = get_third_party_provider(db, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    provider.is_active = False
    
    # Mark all sessions for this provider as inactive
    sessions = db.query(ThirdPartySession).filter(
        ThirdPartySession.provider_id == provider_id,
        ThirdPartySession.is_active == True
    ).all()
    
    for session in sessions:
        session.is_active = False
    
    db.commit()
    
    return {"message": "Provider deactivated successfully"}

# OAuth 2.0 Authorization endpoint (with third-party support)
@app.get("/authorize")
def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    provider: Optional[str] = None,  # Third-party provider name
    db: Session = Depends(get_db)
):
    logger.info(f"OAuth authorization request - client_id: {client_id}, redirect_uri: {redirect_uri}, scope: {scope}, provider: {provider}")
    
    # Validate client
    client = get_oauth_client(db, client_id)
    if not client:
        logger.warning(f"OAuth authorization failed: invalid client_id {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if client.redirect_uri != redirect_uri:
        logger.warning(f"OAuth authorization failed: redirect URI mismatch for client {client_id}")
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    if response_type != "code":
        logger.warning(f"OAuth authorization failed: unsupported response_type {response_type}")
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    # Third-party authorization flow
    if provider:
        logger.info(f"Third-party OAuth flow initiated for provider: {provider}")
        third_party_provider = get_third_party_provider_by_name(db, provider)
        if not third_party_provider:
            logger.warning(f"Invalid third-party provider requested: {provider}")
            raise HTTPException(status_code=400, detail="Invalid third-party provider")
        
        # Create third-party session
        session = create_third_party_session(db, third_party_provider.id, client_id, redirect_uri, state)
        logger.info(f"Created third-party session: {session.session_id} for provider: {provider}")
        
        # Build third-party authorization URL
        third_party_redirect_uri = f"{BASE_URL}/oauth/third-party/callback/{session.session_id}"
        params = {
            "response_type": "code",
            "client_id": third_party_provider.client_id,
            "redirect_uri": third_party_redirect_uri,
            "scope": third_party_provider.scope,
            "state": session.session_id
        }
        
        authorization_url = f"{third_party_provider.authorization_endpoint}?{urllib.parse.urlencode(params)}"
        logger.info(f"Redirecting to third-party authorization URL: {authorization_url}")
        return RedirectResponse(url=authorization_url)
    
    # Standard MCP authorization flow
    logger.info(f"Returning login form for client: {client.name}, redirect_uri: {redirect_uri}")
    # Return login form
    login_form = f"""
    <html>
        <head><title>OAuth Login</title></head>
        <body>
            <h2>Login to {client.name}</h2>
            <form method="post" action="/oauth/login">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="state" value="{state or ''}">
                <p>
                    <label>Username:</label><br>
                    <input type="text" name="username" required>
                </p>
                <p>
                    <label>Password:</label><br>
                    <input type="password" name="password" required>
                </p>
                <p>
                    <input type="submit" value="Login">
                </p>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=login_form)

# OAuth login handler
@app.post("/oauth/login")
def oauth_login(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    # Authenticate user
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Generate authorization code
    auth_code = generate_authorization_code()
    expires_at = datetime.utcnow() + timedelta(minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES)
    
    db_auth_code = AuthorizationCode(
        code=auth_code,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        expires_at=expires_at
    )
    db.add(db_auth_code)
    db.commit()
    
    # Redirect with authorization code
    params = {"code": auth_code}
    if state:
        params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urllib.parse.urlencode(params)}"
    logger.info(f"Redirecting to callback URL: {redirect_url}")
    return RedirectResponse(url=redirect_url, status_code=302)

# Third-party OAuth callback
@app.get("/oauth/third-party/callback/{session_id}")
async def third_party_callback(
    session_id: str,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Validate session
    session = get_third_party_session(db, session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session")
    
    # Check for authorization error
    if error:
        # Redirect back to client with error
        params = {"error": error, "error_description": "Third-party authorization failed"}
        if session.state:
            params["state"] = session.state
        error_url = f"{session.original_redirect_uri}?{urllib.parse.urlencode(params)}"
        return RedirectResponse(url=error_url)
    
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    
    # Get provider
    provider = get_third_party_provider(db, session.provider_id)
    if not provider:
        raise HTTPException(status_code=400, detail="Provider not found")
    
    try:
        # Exchange code for tokens
        redirect_uri = f"{BASE_URL}/oauth/third-party/callback/{session_id}"
        token_response = await exchange_third_party_code(provider, code, redirect_uri)
        
        third_party_access_token = token_response.get("access_token")
        third_party_refresh_token = token_response.get("refresh_token")
        expires_in = token_response.get("expires_in")
        
        if not third_party_access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        # Get user info from third-party
        user_info = await get_third_party_user_info(provider, third_party_access_token)
        third_party_user_id = user_info.get("sub") or user_info.get("id") or user_info.get("user_id")
        
        if not third_party_user_id:
            raise HTTPException(status_code=400, detail="Unable to get user ID from third-party")
        
        # Update session with third-party tokens and user info
        session.third_party_access_token = third_party_access_token
        session.third_party_refresh_token = third_party_refresh_token
        session.third_party_user_id = str(third_party_user_id)
        
        if expires_in:
            session.third_party_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Generate MCP access token bound to this third-party session
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        mcp_access_token = create_access_token(
            data={
                "sub": f"third_party_{provider.name}_{third_party_user_id}",
                "user_id": third_party_user_id,
                "provider": provider.name,
                "session_id": session_id,
                "token_type": "third_party_bound"
            },
            expires_delta=access_token_expires,
            scope="profile email"
        )
        
        session.mcp_access_token = mcp_access_token
        db.commit()
        
        # Generate authorization code for final step
        auth_code = generate_authorization_code()
        expires_at = datetime.utcnow() + timedelta(minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES)
        
        db_auth_code = AuthorizationCode(
            code=auth_code,
            client_id=session.mcp_client_id,
            user_id=0,  # Use 0 for third-party users
            redirect_uri=session.original_redirect_uri,
            expires_at=expires_at
        )
        db.add(db_auth_code)
        db.commit()
        
        # Redirect back to original client with authorization code
        params = {"code": auth_code}
        if session.state:
            params["state"] = session.state
        
        redirect_url = f"{session.original_redirect_uri}?{urllib.parse.urlencode(params)}"
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        # Mark session as inactive on error
        session.is_active = False
        db.commit()
        
        params = {"error": "server_error", "error_description": "Third-party authorization processing failed"}
        if session.state:
            params["state"] = session.state
        error_url = f"{session.original_redirect_uri}?{urllib.parse.urlencode(params)}"
        return RedirectResponse(url=error_url)

# OAuth token endpoint
@app.post("/token")
def get_token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    logger.info(f"Token request - grant_type: {grant_type}, client_id: {client_id}, redirect_uri: {redirect_uri}")
    
    # Verify client
    if not verify_client_secret(db, client_id, client_secret):
        logger.warning(f"Token request failed: invalid client credentials for client_id {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client credentials")
    
    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="Missing code or redirect_uri")
        
        # Find and validate authorization code
        auth_code = db.query(AuthorizationCode).filter(
            AuthorizationCode.code == code,
            AuthorizationCode.client_id == client_id,
            AuthorizationCode.redirect_uri == redirect_uri,
            AuthorizationCode.used == False
        ).first()
        
        if not auth_code:
            logger.warning(f"Token exchange failed: invalid authorization code")
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        if auth_code.expires_at < datetime.utcnow():
            logger.warning(f"Token exchange failed: authorization code expired")
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        logger.info(f"Valid authorization code found, issuing access token for client {client_id}")
        
        # Mark code as used
        auth_code.used = True
        db.commit()
        
        # Handle third-party vs standard users
        if auth_code.user_id == 0:
            # Third-party user - find associated session
            session = db.query(ThirdPartySession).filter(
                ThirdPartySession.mcp_client_id == client_id,
                ThirdPartySession.is_active == True
            ).first()
            
            if not session or not validate_third_party_token_status(db, session):
                raise HTTPException(status_code=400, detail="Invalid or expired third-party session")
            
            # Use the pre-generated MCP token bound to the third-party session
            access_token = session.mcp_access_token
        else:
            # Standard user
            user = get_user_by_id(db, auth_code.user_id)
            if not user:
                raise HTTPException(status_code=400, detail="User not found")
            
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user.username, "user_id": user.id},
                expires_delta=access_token_expires,
                scope="profile email"
            )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

# OAuth 2.0 Token Revocation (RFC 7009)
@app.post("/revoke")
def revoke_token(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    # Verify client if credentials provided
    if client_id and client_secret:
        if not verify_client_secret(db, client_id, client_secret):
            raise HTTPException(status_code=400, detail="Invalid client credentials")
    
    try:
        # Decode token to get information
        payload = jwt.decode(token, public_pem, algorithms=[ALGORITHM])
        token_type = payload.get("token_type")
        session_id = payload.get("session_id")
        
        # Handle third-party bound tokens
        if token_type == "third_party_bound" and session_id:
            session = get_third_party_session(db, session_id)
            if session:
                session.is_active = False
                db.commit()
        
        # For regular tokens, we could maintain a blacklist in production
        # For now, just return success as the token will expire naturally
        
    except JWTError:
        # Token is invalid or malformed - still return success per RFC 7009
        pass
    
    # Always return 200 OK per RFC 7009 (don't leak token validity information)
    return {"message": "Token revocation successful"}

# Direct token endpoint (for testing with password grant)
@app.post("/auth/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id}, 
        expires_delta=access_token_expires,
        scope="profile email"
    )
    return {"access_token": access_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}

# User info endpoint
@app.get("/oauth/userinfo")
def get_user_info(current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    # Get token payload to check scopes
    try:
        payload = jwt.decode(token, public_pem, algorithms=[ALGORITHM])
        scopes = payload.get("scope", "profile email").split()
    except JWTError:
        scopes = ["profile", "email"]  # Default scopes
    
    user_info = {}
    
    # Include profile information if profile scope is present
    if "profile" in scopes:
        user_info.update({
            "sub": str(current_user.id),
            "preferred_username": current_user.username
        })
        
        # Add provider info for third-party users
        if hasattr(current_user, "is_third_party") and current_user.is_third_party:
            user_info["provider"] = current_user.provider
    
    # Include email if email scope is present
    if "email" in scopes:
        user_info.update({
            "email": current_user.email,
            "email_verified": True  # Assume verified for this implementation
        })
    
    return user_info

# Health check
@app.get("/")
def root():
    return {"message": "OAuth IdP Server is running"}

# JWKS endpoint
@app.get("/.well-known/jwks.json")
def jwks():
    # Get RSA public key components
    public_numbers = public_key.public_numbers()
    
    # Convert to base64url encoding
    def int_to_base64url_uint(val):
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('=')
    
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": KEY_ID,
                "use": "sig",
                "alg": ALGORITHM,
                "n": int_to_base64url_uint(public_numbers.n),
                "e": int_to_base64url_uint(public_numbers.e)
            }
        ]
    }

# Well-known OAuth configuration
@app.get("/.well-known/oauth-authorization-server")
def oauth_metadata(db: Session = Depends(get_db)):
    # Get available third-party providers
    providers = db.query(ThirdPartyProvider).filter(ThirdPartyProvider.is_active == True).all()
    provider_names = [provider.name for provider in providers]
    
    metadata = {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "registration_endpoint": f"{BASE_URL}/register",
        "revocation_endpoint": f"{BASE_URL}/revoke",
        "userinfo_endpoint": f"{BASE_URL}/oauth/userinfo",
        "jwks_uri": f"{BASE_URL}/.well-known/jwks.json",
        "scopes_supported": ["profile", "email"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "token_endpoint_auth_signing_alg_values_supported": [ALGORITHM],
        "code_challenge_methods_supported": ["S256"],
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
        "require_request_uri_registration": False,
        "require_pushed_authorization_requests": False,
        "pkce_required": False
    }
    
    # Add MCP third-party authorization extension
    if provider_names:
        metadata["third_party_providers_supported"] = provider_names
        metadata["third_party_authorization_endpoint"] = f"{BASE_URL}/oauth/authorize?provider={{provider_name}}"
        metadata["mcp_third_party_authorization_flow"] = "2025-03-26"
    
    return metadata

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)