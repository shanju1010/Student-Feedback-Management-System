"""SFMS Phase 4 faculty reporting installer. Run from the backend directory."""
from pathlib import Path
import ast

path = Path('app/main.py')
if not path.is_file():
    raise SystemExit('ERROR: Run this script from the backend folder (app/main.py not found).')
original = path.read_text(encoding='utf-8')
marker = '# SFMS PHASE 4 FACULTY API START'
anchor = "FRONTEND_FILE = Path(__file__).resolve().parent.parent / 'frontend' / 'index.html'"
if marker in original:
    raise SystemExit('Phase 4 is already installed; no changes made.')
if anchor not in original:
    raise SystemExit('Expected frontend anchor not found. No changes made; share your current main.py.')
if not Path('app/main_phase3_backup.py').exists() or not Path('sfms_phase3_backup.db').exists():
    raise SystemExit('Phase 3 backups are missing. No changes made.')

addition = '''# SFMS PHASE 4 FACULTY API START
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

'''
updated = original.replace(anchor, addition + anchor, 1)
ast.parse(updated, filename=str(path))
path.write_text(updated, encoding='utf-8')
print('Phase 4 faculty reporting API installed successfully.')
print('Routes: GET /api/faculty/subjects, /api/faculty/summary, /api/faculty/reports')
print('Restart the server, sign in as faculty, and open /docs.')
