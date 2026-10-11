import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, ForeignKey, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./sfms.db')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine)
password_hash = PasswordHasher()

def verify_password(plain: str, stored: str) -> bool:
    try:
        return password_hash.verify(stored, plain)
    except (VerifyMismatchError, VerificationError):
        return False
COOKIE_NAME = 'sfms_session'
SESSION_HOURS = 8

class Base(DeclarativeBase): pass
class Role(str, Enum):
    student = 'student'
    faculty = 'faculty'
    admin = 'admin'

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=Role.student.value)
    is_active: Mapped[bool] = mapped_column(default=True)

class Subject(Base):
    __tablename__ = 'subjects'
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    active: Mapped[bool] = mapped_column(default=True)

class FacultyAssignment(Base):
    __tablename__ = 'faculty_assignments'
    id: Mapped[int] = mapped_column(primary_key=True)
    subject_id: Mapped[int] = mapped_column(ForeignKey('subjects.id'))
    faculty_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    __table_args__ = (UniqueConstraint('subject_id', 'faculty_id'),)

class FeedbackCycle(Base):
    __tablename__ = 'feedback_cycles'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class FeedbackSubmission(Base):
    __tablename__ = 'feedback_submissions'
    id: Mapped[int] = mapped_column(primary_key=True)
    student_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    subject_id: Mapped[int] = mapped_column(ForeignKey('subjects.id'))
    faculty_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    cycle_id: Mapped[int] = mapped_column(ForeignKey('feedback_cycles.id'))
    rating: Mapped[int] = mapped_column(Integer)
    comment: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (UniqueConstraint('student_id', 'subject_id', 'faculty_id', 'cycle_id'),)

class LoginSession(Base):
    __tablename__ = 'login_sessions'
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

Base.metadata.create_all(bind=engine)  # Development bootstrap; replace with Alembic migrations before production.
app = FastAPI(title='SFMS Authentication API')

class LoginInput(BaseModel):
    email: str
    password: str

class UserOutput(BaseModel):
    id: int
    email: str
    role: Role
    model_config = {'from_attributes': True}

def db_session():
    with SessionLocal() as db:
        yield db

def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def authenticated_user(request: Request, db: Session = Depends(db_session)) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, 'Authentication required')
    session = db.query(LoginSession).filter_by(token_hash=digest(token)).first()
    if not session or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise HTTPException(401, 'Session expired or invalid')
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, 'Account unavailable')
    return user

def require_role(*roles: Role):
    def check(user: User = Depends(authenticated_user)) -> User:
        if user.role not in [r.value for r in roles]:
            raise HTTPException(403, 'Insufficient permissions')
        return user
    return check

@app.get('/health')
def health():
    return {'status': 'ok'}

@app.post('/auth/login', response_model=UserOutput)
def login(data: LoginInput, response: Response, db: Session = Depends(db_session)):
    user = db.query(User).filter_by(email=data.email.strip().lower()).first()
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, 'Invalid credentials')
    token = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=digest(token), user_id=user.id, expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)))
    db.commit()
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=os.getenv('COOKIE_SECURE', 'false').lower() == 'true', samesite='lax', max_age=SESSION_HOURS * 3600)
    return user

@app.post('/auth/logout')
def logout(request: Request, response: Response, db: Session = Depends(db_session)):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.query(LoginSession).filter_by(token_hash=digest(token)).delete()
        db.commit()
    response.delete_cookie(COOKIE_NAME, samesite='lax', secure=os.getenv('COOKIE_SECURE', 'false').lower() == 'true')
    return {'message': 'Logged out'}

@app.get('/auth/me', response_model=UserOutput)
def me(user: User = Depends(authenticated_user)):
    return user

@app.get('/admin/check')
def admin_check(user: User = Depends(require_role(Role.admin))):
    return {'message': 'Admin access granted'}

# Serve frontend and API from the same origin so session cookies work without CORS.
FRONTEND_FILE = Path(__file__).resolve().parent.parent / 'frontend' / 'index.html'

@app.get('/', include_in_schema=False)
def frontend_home():
    return FileResponse(FRONTEND_FILE)
