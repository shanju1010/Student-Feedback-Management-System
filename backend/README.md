# SFMS Phase 2 — Real Backend Login + Institutional Frontend

This package includes the existing Phase 1 FastAPI authentication API and the institutional HTML frontend. Login/logout and session restoration now call real backend endpoints; **all subjects, feedback submissions, admin actions, and reports are still browser-local demonstration data**. Do not enter real student records.

## Install on Windows
1. Back up your existing `SFMS/backend` and `SFMS/frontend` folders, especially `backend/sfms.db` if it exists.
2. Copy this package's `frontend` folder to `SFMS/frontend` and the `app` folder to `SFMS/backend/app` (overwrite files when prompted). Keep your existing `backend/sfms.db` and `backend/.venv`; do not replace or delete them.
3. From `SFMS/backend`, run `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload`.
4. Open **http://127.0.0.1:8000/** (not `file:///.../index.html`). Use the database email/password you created with `create_demo_user.py`.
5. Run tests: `.\.venv\Scripts\python.exe -m pytest -q`.

## Security and functionality limits
- Backend login uses Argon2 and an HTTP-only session cookie. Cookie secure flag must be enabled under HTTPS in deployment.
- This local development integration is not production-ready: add CSRF protection, migrations, rate limiting, audit logs, HTTPS, and real backend APIs for course data.
- Demo subjects and reports do not reflect database data; local browser state remains independent of the logged-in backend account. Do not treat UI actions as saved on the server.
- For a real multiuser SFMS, remove the browser-local mock state and implement authenticated subject, enrollment, feedback and reporting endpoints with server-side role checks.
