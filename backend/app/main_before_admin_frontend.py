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



# SFMS PHASE 3 API START

from sqlalchemy.exc import IntegrityError

from sqlalchemy import func



class FeedbackInput(BaseModel):

    subject_id: int = Field(gt=0)

    faculty_id: int = Field(gt=0)

    cycle_id: int = Field(gt=0)

    rating: int = Field(ge=1, le=5)

    comment: str | None = Field(default=None, max_length=1000)





def check_same_origin(request: Request):

    # A session cookie authenticates the user; this additionally blocks

    # cross-origin browser submissions on the state-changing feedback route.

    origin = request.headers.get('origin')

    if origin:

        from urllib.parse import urlsplit

        try:

            source = urlsplit(origin)

            target = urlsplit(str(request.base_url))

            if (source.scheme, source.netloc) != (target.scheme, target.netloc):

                raise HTTPException(403, 'Cross-origin request rejected')

        except ValueError:

            raise HTTPException(403, 'Invalid request origin')

    else:

        # Browsers send Origin for cross-origin requests; reject cross-site

        # requests even when Origin is absent if Fetch Metadata says cross-site.

        if request.headers.get('sec-fetch-site') == 'cross-site':

            raise HTTPException(403, 'Cross-site request rejected')





def as_utc(value: datetime) -> datetime:

    # SQLite commonly returns naive datetime objects for stored UTC values.

    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)





@app.get('/api/subjects')

def api_subjects(

    user: User = Depends(require_role(Role.student, Role.faculty, Role.admin)),

    db: Session = Depends(db_session),

):

    rows = (

        db.query(Subject, FacultyAssignment, User)

        .join(FacultyAssignment, FacultyAssignment.subject_id == Subject.id)

        .join(User, User.id == FacultyAssignment.faculty_id)

        .filter(Subject.active.is_(True), User.is_active.is_(True), User.role == Role.faculty.value)

        .order_by(Subject.code, User.email)

        .all()

    )

    now = datetime.now(timezone.utc)

    cycles = db.query(FeedbackCycle).all()

    active_cycles = [

        {'id': cycle.id, 'name': cycle.name, 'starts_at': as_utc(cycle.starts_at).isoformat(), 'ends_at': as_utc(cycle.ends_at).isoformat()}

        for cycle in cycles

        if as_utc(cycle.starts_at) <= now <= as_utc(cycle.ends_at)

    ]

    return {

        'subjects': [

            {'id': subject.id, 'code': subject.code, 'name': subject.name,

             'faculty_id': faculty.id, 'faculty_email': faculty.email}

            for subject, _assignment, faculty in rows

        ],

        'active_cycles': active_cycles,

    }





@app.post('/api/feedback', status_code=201)

def api_submit_feedback(

    payload: FeedbackInput,

    request: Request,

    user: User = Depends(require_role(Role.student)),

    db: Session = Depends(db_session),

):

    check_same_origin(request)

    subject = db.get(Subject, payload.subject_id)

    if subject is None or not subject.active:

        raise HTTPException(404, 'Subject not found or inactive')

    faculty = db.get(User, payload.faculty_id)

    if faculty is None or not faculty.is_active or faculty.role != Role.faculty.value:

        raise HTTPException(400, 'Invalid faculty account')

    assignment = db.query(FacultyAssignment).filter_by(

        subject_id=payload.subject_id, faculty_id=payload.faculty_id

    ).first()

    if assignment is None:

        raise HTTPException(400, 'Faculty is not assigned to this subject')

    cycle = db.get(FeedbackCycle, payload.cycle_id)

    if cycle is None:

        raise HTTPException(404, 'Feedback cycle not found')

    now = datetime.now(timezone.utc)

    if not (as_utc(cycle.starts_at) <= now <= as_utc(cycle.ends_at)):

        raise HTTPException(400, 'Feedback cycle is not currently active')

    duplicate = db.query(FeedbackSubmission).filter_by(

        student_id=user.id, subject_id=payload.subject_id,

        faculty_id=payload.faculty_id, cycle_id=payload.cycle_id,

    ).first()

    if duplicate:

        raise HTTPException(409, 'Feedback already submitted for this subject, faculty, and cycle')

    submission = FeedbackSubmission(

        student_id=user.id, subject_id=payload.subject_id,

        faculty_id=payload.faculty_id, cycle_id=payload.cycle_id,

        rating=payload.rating, comment=payload.comment,

        created_at=now,

    )

    db.add(submission)

    try:

        db.commit()

        db.refresh(submission)

    except IntegrityError:

        db.rollback()

        raise HTTPException(409, 'Feedback already submitted')

    return {'id': submission.id, 'message': 'Feedback submitted successfully'}





@app.get('/api/feedback/mine')

def api_my_feedback(

    user: User = Depends(require_role(Role.student)),

    db: Session = Depends(db_session),

):

    rows = (

        db.query(FeedbackSubmission, Subject, User, FeedbackCycle)

        .join(Subject, FeedbackSubmission.subject_id == Subject.id)

        .join(User, FeedbackSubmission.faculty_id == User.id)

        .join(FeedbackCycle, FeedbackSubmission.cycle_id == FeedbackCycle.id)

        .filter(FeedbackSubmission.student_id == user.id)

        .order_by(FeedbackSubmission.created_at.desc())

        .all()

    )

    return {'submissions': [

        {'id': feedback.id, 'subject_id': subject.id, 'subject_code': subject.code,

         'subject_name': subject.name, 'faculty_id': faculty.id,

         'faculty_email': faculty.email, 'cycle_id': cycle.id,

         'cycle_name': cycle.name, 'rating': feedback.rating,

         'comment': feedback.comment, 'created_at': as_utc(feedback.created_at).isoformat()}

        for feedback, subject, faculty, cycle in rows

    ]}

# SFMS PHASE 3 API END



# Serve frontend and API from the same origin so session cookies work without CORS.

# SFMS PHASE 4 FACULTY API START

from sqlalchemy import func as sql_func



# Privacy safeguard: hide granular ratings until there are at least 3 responses.

FACULTY_MIN_REPORT_RESPONSES = 3





def faculty_assigned_subjects(db: Session, faculty_id: int):

    return (

        db.query(Subject)

        .join(FacultyAssignment, FacultyAssignment.subject_id == Subject.id)

        .filter(FacultyAssignment.faculty_id == faculty_id, Subject.active.is_(True))

        .order_by(Subject.code)

        .all()

    )





def faculty_report_rows(db: Session, faculty_id: int):

    # Every query is constrained to the logged-in faculty member.

    subjects = faculty_assigned_subjects(db, faculty_id)

    results = []

    for s in subjects:

        rows = (

            db.query(FeedbackSubmission.rating)

            .filter(

                FeedbackSubmission.subject_id == s.id,

                FeedbackSubmission.faculty_id == faculty_id,

            )

            .all()

        )

        ratings = [r[0] for r in rows]

        count = len(ratings)

        reportable = count >= FACULTY_MIN_REPORT_RESPONSES

        results.append({

            'subject_id': s.id,

            'subject_code': s.code,

            'subject_name': s.name,

            'response_count': count,

            'average_rating': round(sum(ratings) / count, 2) if reportable else None,

            'rating_distribution': {str(n): ratings.count(n) for n in range(1, 6)} if reportable else None,

            'privacy_suppressed': not reportable,

        })

    return results





@app.get('/api/faculty/subjects')

def api_faculty_subjects(

    user: User = Depends(require_role(Role.faculty)),

    db: Session = Depends(db_session),

):

    return {'subjects': [

        {'id': s.id, 'code': s.code, 'name': s.name}

        for s in faculty_assigned_subjects(db, user.id)

    ]}





@app.get('/api/faculty/summary')

def api_faculty_summary(

    user: User = Depends(require_role(Role.faculty)),

    db: Session = Depends(db_session),

):

    reports = faculty_report_rows(db, user.id)

    total = sum(r['response_count'] for r in reports)

    # Suppress cross-subject averages if fewer than 3 total responses.

    all_ratings = (

        db.query(FeedbackSubmission.rating)

        .join(FacultyAssignment,

              (FacultyAssignment.subject_id == FeedbackSubmission.subject_id) &

              (FacultyAssignment.faculty_id == FeedbackSubmission.faculty_id))

        .filter(FeedbackSubmission.faculty_id == user.id)

        .all()

    )

    ratings = [r[0] for r in all_ratings]

    return {

        'assigned_subjects': len(reports),

        'total_responses': total,

        'subjects_with_responses': sum(1 for r in reports if r['response_count'] > 0),

        'average_rating': round(sum(ratings) / len(ratings), 2) if len(ratings) >= FACULTY_MIN_REPORT_RESPONSES else None,

        'privacy_suppressed': len(ratings) < FACULTY_MIN_REPORT_RESPONSES,

        'minimum_report_responses': FACULTY_MIN_REPORT_RESPONSES,

    }





@app.get('/api/faculty/reports')

def api_faculty_reports(

    user: User = Depends(require_role(Role.faculty)),

    db: Session = Depends(db_session),

):

    return {

        'minimum_report_responses': FACULTY_MIN_REPORT_RESPONSES,

        'reports': faculty_report_rows(db, user.id),

    }

# SFMS PHASE 4 FACULTY API END



# SFMS PHASE 5 ADMIN READ-ONLY API START

# These endpoints intentionally exclude password hashes, session tokens,

# student feedback comments, and individual feedback ratings.



@app.get('/api/admin/summary')

def api_admin_summary(

    user: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    return {

        'total_users': db.query(User).count(),

        'active_users': db.query(User).filter(User.is_active.is_(True)).count(),

        'total_subjects': db.query(Subject).count(),

        'active_subjects': db.query(Subject).filter(Subject.active.is_(True)).count(),

        'faculty_assignments': db.query(FacultyAssignment).count(),

        'feedback_cycles': db.query(FeedbackCycle).count(),

        'total_responses': db.query(FeedbackSubmission).count(),

    }





@app.get('/api/admin/users')

def api_admin_users(

    user: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    return {'users': [

        {'id': u.id, 'email': u.email, 'role': u.role, 'is_active': u.is_active}

        for u in db.query(User).order_by(User.id).all()

    ]}





@app.get('/api/admin/subjects')

def api_admin_subjects(

    user: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    subjects = db.query(Subject).order_by(Subject.code).all()

    assignments = db.query(FacultyAssignment, User).join(

        User, User.id == FacultyAssignment.faculty_id

    ).all()

    by_subject = {}

    for assignment, faculty in assignments:

        by_subject.setdefault(assignment.subject_id, []).append({

            'faculty_id': faculty.id, 'faculty_email': faculty.email,

        })

    return {'subjects': [

        {'id': s.id, 'code': s.code, 'name': s.name,

         'active': s.active, 'faculty': by_subject.get(s.id, [])}

        for s in subjects

    ]}





@app.get('/api/admin/cycles')

def api_admin_cycles(

    user: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    return {'cycles': [

        {'id': c.id, 'name': c.name,

         'starts_at': as_utc(c.starts_at).isoformat(),

         'ends_at': as_utc(c.ends_at).isoformat()}

        for c in db.query(FeedbackCycle).order_by(FeedbackCycle.id).all()

    ]}



# SFMS PHASE 5 ADMIN READ-ONLY API END



# SFMS PHASE 5 ADMIN ACCOUNT CREATION START

class AdminCreateUserInput(BaseModel):

    email: EmailStr

    password: str = Field(min_length=12, max_length=128)

    role: Role





@app.post('/api/admin/users', status_code=201, response_model=UserOutput)

def api_admin_create_user(

    payload: AdminCreateUserInput,

    request: Request,

    admin: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    # This endpoint uses session cookies, so require same-origin requests.

    check_same_origin(request)

    email = str(payload.email).strip().lower()

    if db.query(User).filter_by(email=email).first():

        raise HTTPException(409, 'An account with this email already exists')



    new_user = User(

        email=email,

        password_hash=password_hash.hash(payload.password),

        role=payload.role.value,

        is_active=True,

    )

    db.add(new_user)

    try:

        db.commit()

        db.refresh(new_user)

    except IntegrityError:

        db.rollback()

        raise HTTPException(409, 'An account with this email already exists')

    return new_user

# SFMS PHASE 5 ADMIN ACCOUNT CREATION END



# SFMS PHASE 5 ADMIN USER STATUS MANAGEMENT START

class AdminUserStatusInput(BaseModel):

    is_active: bool





@app.patch('/api/admin/users/{user_id}/status')

def api_admin_update_user_status(

    user_id: int,

    payload: AdminUserStatusInput,

    request: Request,

    admin: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    # Cookie-authenticated writes must originate from this application.

    check_same_origin(request)

    target = db.get(User, user_id)

    if target is None:

        raise HTTPException(404, 'User not found')

    if target.id == admin.id and not payload.is_active:

        raise HTTPException(400, 'You cannot deactivate your own administrator account')

    if target.role == Role.admin.value and target.is_active and not payload.is_active:

        other_active_admins = db.query(User).filter(

            User.role == Role.admin.value,

            User.is_active.is_(True),

            User.id != target.id,

        ).count()

        if other_active_admins == 0:

            raise HTTPException(400, 'Cannot deactivate the last active administrator')



    target.is_active = payload.is_active

    if not payload.is_active:

        # Revoke existing sessions immediately for the disabled account.

        db.query(LoginSession).filter(LoginSession.user_id == target.id).delete(synchronize_session=False)

    db.commit()

    db.refresh(target)

    return {

        'id': target.id,

        'email': target.email,

        'role': target.role,

        'is_active': target.is_active,

    }

# SFMS PHASE 5 ADMIN USER STATUS MANAGEMENT END





# SFMS PHASE 5.4 - ADMIN SUBJECT CREATION



class AdminCreateSubjectInput(BaseModel):

    code: str = Field(min_length=2, max_length=30)

    name: str = Field(min_length=2, max_length=200)





@app.post('/api/admin/subjects', status_code=201)

def api_admin_create_subject(

    payload: AdminCreateSubjectInput,

    request: Request,

    admin: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    check_same_origin(request)



    code = payload.code.strip().upper()

    name = payload.name.strip()



    if len(code) < 2 or len(name) < 2:

        raise HTTPException(422, 'Subject code and name must contain at least 2 characters')



    if db.query(Subject).filter_by(code=code).first():

        raise HTTPException(409, 'A subject with this code already exists')



    subject = Subject(

        code=code,

        name=name,

        active=True,

    )



    db.add(subject)



    try:

        db.commit()

        db.refresh(subject)

    except IntegrityError:

        db.rollback()

        raise HTTPException(409, 'A subject with this code already exists')



    return {

        'id': subject.id,

        'code': subject.code,

        'name': subject.name,

        'active': subject.active,

    }



# SFMS PHASE 5.4 - END



# SFMS PHASE 5.4 - ADMIN SUBJECT EDITING



class AdminUpdateSubjectInput(BaseModel):

    code: str | None = Field(default=None, min_length=2, max_length=30)

    name: str | None = Field(default=None, min_length=2, max_length=200)





@app.patch('/api/admin/subjects/{subject_id}')

def api_admin_update_subject(

    subject_id: int,

    payload: AdminUpdateSubjectInput,

    request: Request,

    admin: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    check_same_origin(request)



    subject = db.get(Subject, subject_id)



    if subject is None:

        raise HTTPException(404, 'Subject not found')



    if payload.code is None and payload.name is None:

        raise HTTPException(422, 'Provide a code or name to update')



    if payload.code is not None:

        code = payload.code.strip().upper()



        if len(code) < 2:

            raise HTTPException(422, 'Invalid subject code')



        duplicate = db.query(Subject).filter(

            Subject.code == code,

            Subject.id != subject_id,

        ).first()



        if duplicate:

            raise HTTPException(409, 'A subject with this code already exists')



        subject.code = code



    if payload.name is not None:

        name = payload.name.strip()



        if len(name) < 2:

            raise HTTPException(422, 'Invalid subject name')



        subject.name = name



    try:

        db.commit()

        db.refresh(subject)

    except IntegrityError:

        db.rollback()

        raise HTTPException(409, 'A subject with this code already exists')



    return {

        'id': subject.id,

        'code': subject.code,

        'name': subject.name,

        'active': subject.active,

    }



# SFMS PHASE 5.4 - SUBJECT EDITING END





# SFMS PHASE 5.4 - ADMIN SUBJECT STATUS



class AdminSubjectStatusInput(BaseModel):

    active: bool





@app.patch('/api/admin/subjects/{subject_id}/status')

def api_admin_subject_status(

    subject_id: int,

    payload: AdminSubjectStatusInput,

    request: Request,

    admin: User = Depends(require_role(Role.admin)),

    db: Session = Depends(db_session),

):

    check_same_origin(request)



    subject = db.get(Subject, subject_id)



    if subject is None:

        raise HTTPException(404, 'Subject not found')



    subject.active = payload.active



    db.commit()

    db.refresh(subject)



    return {

        'id': subject.id,

        'code': subject.code,

        'name': subject.name,

        'active': subject.active,

    }



# SFMS PHASE 5.4 - SUBJECT STATUS END











# SFMS PHASE 5.5 / 5.6 - FACULTY ASSIGNMENTS AND FEEDBACK CYCLES
# All changes are administrator-only and preserve existing feedback records.

class AdminFacultyAssignmentInput(BaseModel):
    subject_id: int = Field(gt=0)
    faculty_id: int = Field(gt=0)


@app.post('/api/admin/assignments', status_code=201)
def api_admin_create_assignment(
    payload: AdminFacultyAssignmentInput,
    request: Request,
    admin: User = Depends(require_role(Role.admin)),
    db: Session = Depends(db_session),
):
    check_same_origin(request)
    subject = db.get(Subject, payload.subject_id)
    if subject is None:
        raise HTTPException(404, 'Subject not found')
    if not subject.active:
        raise HTTPException(400, 'Cannot assign faculty to an inactive subject')
    faculty = db.get(User, payload.faculty_id)
    if faculty is None or faculty.role != Role.faculty.value or not faculty.is_active:
        raise HTTPException(400, 'Faculty account not found, inactive, or not a faculty member')
    if db.query(FacultyAssignment).filter_by(subject_id=subject.id, faculty_id=faculty.id).first():
        raise HTTPException(409, 'Faculty is already assigned to this subject')
    assignment = FacultyAssignment(subject_id=subject.id, faculty_id=faculty.id)
    db.add(assignment)
    try:
        db.commit()
        db.refresh(assignment)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Faculty is already assigned to this subject')
    return {
        'id': assignment.id, 'subject_id': subject.id, 'subject_code': subject.code,
        'faculty_id': faculty.id, 'faculty_email': faculty.email,
    }


@app.delete('/api/admin/assignments/{assignment_id}')
def api_admin_remove_assignment(
    assignment_id: int,
    request: Request,
    admin: User = Depends(require_role(Role.admin)),
    db: Session = Depends(db_session),
):
    check_same_origin(request)
    assignment = db.get(FacultyAssignment, assignment_id)
    if assignment is None:
        raise HTTPException(404, 'Faculty assignment not found')
    # Historical reports must continue to reflect the faculty/subject relationship.
    has_feedback = db.query(FeedbackSubmission.id).filter_by(
        subject_id=assignment.subject_id, faculty_id=assignment.faculty_id
    ).first()
    if has_feedback:
        raise HTTPException(409, 'Cannot remove an assignment with feedback history')
    db.delete(assignment)
    db.commit()
    return {'message': 'Faculty assignment removed', 'id': assignment_id}


class AdminCreateCycleInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    starts_at: datetime
    ends_at: datetime


def validate_cycle_dates(starts_at: datetime, ends_at: datetime):
    if starts_at.tzinfo is None or starts_at.utcoffset() is None:
        raise HTTPException(422, 'starts_at must include a timezone offset')
    if ends_at.tzinfo is None or ends_at.utcoffset() is None:
        raise HTTPException(422, 'ends_at must include a timezone offset')
    if starts_at >= ends_at:
        raise HTTPException(422, 'ends_at must be later than starts_at')


def cycle_result(cycle: FeedbackCycle):
    return {
        'id': cycle.id, 'name': cycle.name,
        'starts_at': as_utc(cycle.starts_at).isoformat(),
        'ends_at': as_utc(cycle.ends_at).isoformat(),
    }


@app.post('/api/admin/cycles', status_code=201)
def api_admin_create_cycle(
    payload: AdminCreateCycleInput,
    request: Request,
    admin: User = Depends(require_role(Role.admin)),
    db: Session = Depends(db_session),
):
    check_same_origin(request)
    validate_cycle_dates(payload.starts_at, payload.ends_at)
    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(422, 'Cycle name must contain at least 2 characters')
    cycle = FeedbackCycle(
        name=name,
        starts_at=payload.starts_at.astimezone(timezone.utc),
        ends_at=payload.ends_at.astimezone(timezone.utc),
    )
    db.add(cycle)
    db.commit()
    db.refresh(cycle)
    return cycle_result(cycle)


class AdminUpdateCycleInput(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    starts_at: datetime | None = None
    ends_at: datetime | None = None


@app.patch('/api/admin/cycles/{cycle_id}')
def api_admin_update_cycle(
    cycle_id: int,
    payload: AdminUpdateCycleInput,
    request: Request,
    admin: User = Depends(require_role(Role.admin)),
    db: Session = Depends(db_session),
):
    check_same_origin(request)
    cycle = db.get(FeedbackCycle, cycle_id)
    if cycle is None:
        raise HTTPException(404, 'Feedback cycle not found')
    changes = payload.model_dump(exclude_unset=True)
    if not changes or any(value is None for value in changes.values()):
        raise HTTPException(422, 'Provide non-null fields to update')
    # Prevent changing a feedback period after students have submitted responses.
    if db.query(FeedbackSubmission.id).filter_by(cycle_id=cycle_id).first():
        raise HTTPException(409, 'Cannot edit a feedback cycle with existing submissions')
    name = changes.get('name', cycle.name)
    name = name.strip()
    if len(name) < 2:
        raise HTTPException(422, 'Cycle name must contain at least 2 characters')
    starts_at = changes.get('starts_at', as_utc(cycle.starts_at))
    ends_at = changes.get('ends_at', as_utc(cycle.ends_at))
    validate_cycle_dates(starts_at, ends_at)
    cycle.name = name
    cycle.starts_at = starts_at.astimezone(timezone.utc)
    cycle.ends_at = ends_at.astimezone(timezone.utc)
    db.commit()
    db.refresh(cycle)
    return cycle_result(cycle)

# END SFMS PHASE 5.5 / 5.6


FRONTEND_FILE = Path(__file__).resolve().parent.parent / 'frontend' / 'index.html'



@app.get('/', include_in_schema=False)

def frontend_home():

    return FileResponse(FRONTEND_FILE)
