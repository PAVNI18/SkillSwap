# SkillSwap

SkillSwap is a peer-to-peer learning platform made as a college project. The idea is simple: every student knows something, and every student wants to learn something. SkillSwap helps them find the right person to exchange skills with.

**The right skill is just a swap away.**

## About the project

Learning a new skill can be difficult when courses, mentors, or learning partners are not easily available. At the same time, many students already have useful skills they can share. SkillSwap brings these students together so they can teach, learn, and grow through real connections.

After creating a profile, users add the skill they can teach, the skill they want to learn, their level, and their availability. The platform then suggests people with complementary skills. Users can show interest, connect, chat, plan sessions, and share feedback after a session is completed.

## Features

- User and admin login
- Profile creation with skills, level, and availability
- Certificate upload and verification
- Match suggestions and swipe-style preference cards
- Connection requests, chat, and session scheduling
- Session feedback and star ratings
- Completion certificates
- Notifications and account controls
- Admin dashboard for reviewing certificates, users, reports, and exchanges
- Demo profiles for showing the matching feature during a presentation

## Built with

- Python and Flask
- MongoDB
- HTML, CSS, JavaScript, and Jinja templates

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

## Demo profiles

To create twenty safe demo learner cards for the Discover Matches screen, run:

```bash
python3 seed_demo_profiles.py
```

This adds sample users with different skills and levels, so the matching feature can be demonstrated easily.

## Notes

- This project is for educational and demonstration purposes.
- Personal uploads, passwords, and environment settings are not included in the repository.
