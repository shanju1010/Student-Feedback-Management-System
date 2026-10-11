"""Install Phase 3 feedback API routes into the existing SFMS app/main.py.
Run from the backend directory: .\.venv\Scripts\python.exe install_phase3.py
"""
from pathlib import Path
import ast
import shutil

path = Path('app/main.py')
if not path.is_file():
    raise SystemExit('ERROR: Run this script from your SFMS backend folder (app/main.py not found).')
original = path.read_text(encoding='utf-8')
if '# SFMS PHASE 3 API START' in original:
    raise SystemExit('Phase 3 routes are already installed. No changes made.')
anchor = '# Serve frontend and API from the same origin so session cookies work without CORS.'
if anchor not in original or 'def authenticated_user(' not in original or 'class FeedbackSubmission(' not in original:
    raise SystemExit('Unexpected main.py structure. No changes made.')

addition = '''# SFMS PHASE 3 API START
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

'''
updated = original.replace(anchor, addition + anchor, 1)
ast.parse(updated, filename=str(path))
backup = path.with_name('main_phase2_backup.py')
if backup.exists():
    raise SystemExit('Backup app/main_phase2_backup.py already exists. No changes made.')
shutil.copy2(path, backup)
path.write_text(updated, encoding='utf-8')
print('Phase 3 API installed successfully.')
print('Backup:', backup)
print('Routes: GET /api/subjects, POST /api/feedback, GET /api/feedback/mine')
print('Restart FastAPI, then open http://127.0.0.1:8000/docs')
