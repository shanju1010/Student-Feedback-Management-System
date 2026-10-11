# Student Feedback Management System (SFMS)

A role-based web application for collecting and managing academic feedback. Built as a college mini-project, SFMS lets students submit subject feedback, faculty view privacy-aware aggregated reports, and administrators manage users, subjects, faculty assignments, and feedback cycles.

> **Project status:** Core workflows have been tested locally. This is a demonstration/academic project, not a production-ready institutional deployment.

## Features

### Student
- Sign in and view active subjects and available feedback cycles.
- Submit a rating for an assigned faculty member and subject during an active cycle.
- View previously submitted feedback.
- Duplicate submissions for the same subject, faculty member, and cycle are prevented.

### Faculty
- View assigned subjects.
- See aggregate feedback summaries and reports for assigned subjects.
- Export reports to CSV.
- Protect respondent privacy: detailed statistics are suppressed when fewer than three responses are available.

### Administrator
- View system-wide summary statistics.
- Create users and manage account activation.
- Create, edit, activate, and deactivate subjects.
- Assign faculty to subjects.
- Create and view feedback cycles.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python, FastAPI |
| ORM | SQLAlchemy |
| Database | SQLite |
| Authentication | Argon2 password hashing, HttpOnly session cookies |
| Frontend | HTML, CSS, vanilla JavaScript |
| API documentation | FastAPI / Swagger UI |

## Architecture

```text
Browser (HTML / CSS / JavaScript)
               |
               | HTTP requests / session cookie
               v
         FastAPI backend
               |
         SQLAlchemy ORM
               |
          SQLite database
```

The application implements role-based authorization for student, faculty, and administrator endpoints.

## Getting Started (Windows / PowerShell)

### 1. Clone the repository

```powershell
git clone https://github.com/shanju1010/Student-Feedback-Management-System.git
cd Student-Feedback-Management-System\backend
```

### 2. Create and activate a virtual environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

If the repository includes `requirements.txt`, run:

```powershell
pip install -r requirements.txt
```

Otherwise, install the core packages used by this project:

```powershell
pip install fastapi "uvicorn[standard]" sqlalchemy argon2-cffi email-validator
```

### 4. Start the application

```powershell
python -m uvicorn app.main:app --reload
```

Open:
- **Web application:** http://127.0.0.1:8000/
- **API documentation:** http://127.0.0.1:8000/docs

> **First-time setup:** The local database and initial test accounts are not included in this repository. Depending on the current application version, initial users and feedback cycles may require a separate setup/seed procedure. Do not assume the app ships with usable default credentials.

## Main Data Entities

- **User:** student, faculty, or administrator account.
- **Subject:** academic subject, code, and active status.
- **FacultyAssignment:** links faculty members to subjects.
- **FeedbackCycle:** defines the date window for collecting feedback.
- **FeedbackSubmission:** stores feedback ratings associated with the relevant student, faculty member, subject, and cycle.
- **LoginSession:** tracks authenticated sessions.

## Local Demo Workflow

1. Sign in as an administrator and review subjects and faculty assignments.
2. Create or inspect a feedback cycle.
3. Sign in as a student and locate an active subject and cycle.
4. Submit feedback and confirm that duplicate submission is rejected.
5. Sign in as the assigned faculty member and inspect the aggregate report.

**Privacy note:** Reports should not expose individual student identities or raw submissions to faculty. Small-sample details are restricted.

## Security and Data Handling

- Passwords are hashed using Argon2.
- Sessions use HttpOnly cookies.
- Server endpoints enforce role-based access restrictions.
- The SQLite database (`*.db`), virtual environments, environment files, and backup ZIP files should remain outside Git version control.
- Do not commit real student records, test passwords, API keys, or secrets.

This project requires additional security review, deployment configuration, database migration planning, and testing before use with real institutional data.

## Project Repository

[github.com/shanju1010/Student-Feedback-Management-System](https://github.com/shanju1010/Student-Feedback-Management-System)

## License

No license has been specified yet. All rights are reserved unless a license is added to the repository.
