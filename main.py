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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
load_dotenv()

# Environment variables
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./oauth_idp.db")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Generate RSA key pair for JWT signing (in production, use persistent keys)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

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

print(f"Server starting on port {PORT}")
print(f"JWT Key ID: {KEY_ID}")
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

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": BASE_URL,
        "kid": KEY_ID
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
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
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
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# OAuth Client functions
def get_oauth_client(db: Session, client_id: str):
    return db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

def verify_client_secret(db: Session, client_id: str, client_secret: str):
    client = get_oauth_client(db, client_id)
    if not client:
        return False
    return hashlib.sha256(client_secret.encode()).hexdigest() == client.client_secret

# API Endpoints

# User registration (for testing - remove in production)
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    # Check if user exists
    if get_user(db, username):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Create new user
    hashed_password = get_password_hash(password)
    db_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "User created successfully"}

# OAuth client registration (for testing - remove in production)
@app.post("/register_client")
def register_client(name: str = Form(...), redirect_uri: str = Form(...), db: Session = Depends(get_db)):
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

# OAuth 2.0 Authorization endpoint
@app.get("/oauth/authorize")
def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Validate client
    client = get_oauth_client(db, client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if client.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
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
    return RedirectResponse(url=redirect_url)

# OAuth token endpoint
@app.post("/oauth/token")
def get_token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    # Verify client
    if not verify_client_secret(db, client_id, client_secret):
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
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        if auth_code.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Mark code as used
        auth_code.used = True
        db.commit()
        
        # Get user
        user = get_user_by_id(db, auth_code.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id},
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

# Direct token endpoint (for testing)
@app.post("/token")
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
        data={"sub": user.username, "user_id": user.id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}

# User info endpoint
@app.get("/oauth/userinfo")
def get_user_info(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email
    }

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
def oauth_metadata():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "userinfo_endpoint": f"{BASE_URL}/oauth/userinfo",
        "jwks_uri": f"{BASE_URL}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "id_token_signing_alg_values_supported": [ALGORITHM]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)