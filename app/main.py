from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from pydantic_settings import BaseSettings
import os

# -------------------- Settings --------------------
class Settings(BaseSettings):
    SECRET_KEY: str = "change_me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"
    DATABASE_URL: str = "sqlite:///./app.db"
    SECURE_STREAM_BASE: str = "http://127.0.0.1:8000/stream"

    class Config:
        env_file = ".env"

settings = Settings()

# -------------------- App --------------------
app = FastAPI(title="Media Platform API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Database --------------------
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -------------------- Security --------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# -------------------- Models --------------------
class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class MediaAsset(Base):
    __tablename__ = "media_assets"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    type = Column(String, nullable=False)  # "video" or "audio"
    file_url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    views = relationship("MediaViewLog", back_populates="media", cascade="all, delete-orphan")


class MediaViewLog(Base):
    __tablename__ = "media_view_logs"

    id = Column(Integer, primary_key=True)
    media_id = Column(Integer, ForeignKey("media_assets.id", ondelete="CASCADE"), index=True, nullable=False)
    viewed_by_ip = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    media = relationship("MediaAsset", back_populates="views")


Base.metadata.create_all(bind=engine)

# -------------------- Schemas --------------------
class SignupIn(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MediaCreate(BaseModel):
    title: str
    type: str  # validate client-side: "video" or "audio"
    file_url: str


class MediaOut(BaseModel):
    id: int
    title: str
    type: str
    file_url: str
    created_at: datetime

    class Config:
        from_attributes = True


# -------------------- Auth helpers --------------------

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> AdminUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: Optional[str] = str(payload.get("sub")) if payload.get("sub") is not None else None
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.get(AdminUser, int(user_id))
    if user is None:
        raise credentials_exception
    return user

# -------------------- Routes: Auth --------------------
@app.post("/auth/signup", response_model=UserOut, status_code=201)
def signup(payload: SignupIn, db: Session = Depends(get_db)):
    # Ensure unique email
    exists = db.query(AdminUser).filter(AdminUser.email == payload.email).first()
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = AdminUser(email=payload.email, hashed_password=get_password_hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_access_token({"sub": str(user.id)})
    return TokenOut(access_token=token)


# -------------------- Routes: Media --------------------
@app.post("/media", response_model=MediaOut, status_code=201)
def create_media(item: MediaCreate, db: Session = Depends(get_db), current: AdminUser = Depends(get_current_user)):
    if item.type not in ("video", "audio"):
        raise HTTPException(status_code=422, detail="type must be 'video' or 'audio'")

    media = MediaAsset(title=item.title, type=item.type, file_url=item.file_url)
    db.add(media)
    db.commit()
    db.refresh(media)
    return media


@app.get("/media/{media_id}/stream-url")
def get_stream_url(media_id: int, db: Session = Depends(get_db), current: AdminUser = Depends(get_current_user)):
    media = db.get(MediaAsset, media_id)
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    # Create a short-lived token that encodes media_id and file_url
    expire = datetime.now(timezone.utc) + timedelta(minutes=10)
    token = jwt.encode(
        {"mid": media.id, "f": media.file_url, "exp": expire},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    # Signed URL that your player would call
    url = f"{settings.SECURE_STREAM_BASE}?token={token}"
    return {"stream_url": url, "valid_for_minutes": 10}


# -------------------- Bonus: validate token & log view --------------------
from fastapi.responses import RedirectResponse

@app.get("/stream")
def stream(token: str, request: Request, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        media_id = int(payload.get("mid"))
        file_url = payload.get("f")
        if not media_id or not file_url:
            raise HTTPException(status_code=400, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    media = db.get(MediaAsset, media_id)
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    # Log the view
    ip = request.client.host if request.client else "unknown"
    log = MediaViewLog(media_id=media.id, viewed_by_ip=ip)
    db.add(log)
    db.commit()

    # Redirect to actual file location (CDN/object storage)
    return RedirectResponse(url=file_url)


# -------------------- Health --------------------
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
