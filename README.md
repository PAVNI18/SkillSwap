# SkillSwap

SkillSwap is a college project that helps learners exchange complementary skills through profiles, matching, shared sessions, feedback, and completion certificates.

## Features

- User and administrator login flows
- One-time user and administrator terms agreements
- Certificate upload and profile-detail verification
- Skill matching, requests, chat, and shared schedules
- Session and exchange ratings
- Completion certificates
- Administrator review for certificates, reports, users, and exchanges
- User data export, certificate removal, and account deletion
- First-time SkillSwapping preference card deck

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

## Notes

- Uploaded certificates and profile photos are intentionally excluded from Git.
- Environment values, passwords, SMTP settings, and browser-push keys belong only in `.env` and must never be committed.
