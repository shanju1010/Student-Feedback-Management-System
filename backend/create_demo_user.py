import getpass
from app.main import SessionLocal, User, Role, password_hash
email = input('Email: ').strip().lower()
role = input('Role (student/faculty/admin): ').strip().lower()
if role not in [r.value for r in Role]:
    raise SystemExit('Invalid role')
password = getpass.getpass('Password (at least 12 characters): ')
if len(password) < 12:
    raise SystemExit('Password must be at least 12 characters')
with SessionLocal() as db:
    if db.query(User).filter_by(email=email).first():
        raise SystemExit('Email already exists')
    db.add(User(email=email, password_hash=password_hash.hash(password), role=role))
    db.commit()
print('Local development user created')
