# SkillSwap

SkillSwap is a peer-to-peer skill-exchange platform built as a college project. It helps learners find people with complementary skills, arrange learning sessions, exchange knowledge, and build a trusted learning community.

> **The right skill is just a swap away.**

## Problem statement

Students often want to learn practical skills but may not have access to suitable courses, mentors, or learning partners. At the same time, they already have skills that other students want to learn. SkillSwap connects these two groups and makes learning more social, practical, and accessible.

## How SkillSwap works

1. A user creates a profile with the skill they can teach, the skill they want to learn, their level, and availability.
2. The user uploads a certificate for profile verification.
3. SkillSwap recommends compatible learners with complementary skills.
4. Users can select or pass on suggested profiles, send requests, chat, and plan sessions.
5. After a session, the learner can share feedback and give a star rating.
6. Completed exchanges can include a completion certificate and contribute to the learner's reputation.

## Main features

- Separate user and administrator login flows
- One-time terms and conditions for users and administrators
- Certificate upload and profile-detail verification
- Certificate formats supported: JPG, JPEG, PNG, and PDF (up to 10 MB)
- Complementary-skill matching and first-time swipe/select card deck
- Interest requests, connections, chat, and shared schedules
- Session feedback and 1–5 star ratings
- Completion certificates for finished exchanges
- Notifications for upcoming actions and session feedback
- Administrator review for certificates, reports, users, and exchanges
- User controls for data export, certificate removal, and account deletion
- Twenty clearly marked demo profiles for project demonstrations

## User roles

### Learner

Learners create a skill profile, upload a certificate, discover suitable matches, manage skill exchanges, schedule sessions, and rate completed sessions.

### Administrator

Administrators review flagged certificate submissions, monitor reported content, manage users and exchanges, and help maintain a safe community.

## Technology used

- **Backend:** Python and Flask
- **Database:** MongoDB
- **Frontend:** HTML, CSS, JavaScript, and Jinja templates
- **Security utilities:** Werkzeug password hashing, CSRF protection, and environment-based configuration

## Run locally

1. Install and start MongoDB locally on port `27017`.
2. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install project packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and set at least `FLASK_SECRET_KEY`.
5. Start the application:

   ```bash
   python3 app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## College demo profiles

To create twenty safe demo learner cards for the Discover Matches screen, run:

```bash
python3 seed_demo_profiles.py
```

They include reciprocal UI/UX ↔ Web Development matches and varied skill-exploration cards at beginner, intermediate, and advanced levels. All use `@skillswap.local` addresses and are clearly marked as demo profiles.

## Suggested screenshots

For a project presentation, add screenshots of these pages in this README:

- Home page and Today's Match card
- SkillSwap preference cards
- User dashboard
- Discover Matches screen
- Certificate verification status
- Administrator dashboard

Store them in a `screenshots/` folder and link them here after adding them.

## Notes

- Uploaded certificates and profile photos are intentionally excluded from Git.
- Environment values, passwords, SMTP settings, and browser-push keys belong only in `.env` and must never be committed.
- This project is intended for educational and demonstration purposes.
