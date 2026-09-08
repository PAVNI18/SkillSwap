from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_from_directory,
    abort
)
from models.database import (
    users_collection,
    matches_collection,
    messages_collection,
    reviews_collection,
    badges_collection,
    sessions_collection,
    notifications_collection,
    activities_collection,
    reports_collection
)
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4
from io import BytesIO
from werkzeug.utils import secure_filename
from functools import wraps
import hashlib
import json
import os
import re
import random
import secrets
import shutil
import smtplib
import ssl
import time
import unicodedata
from email.message import EmailMessage

import fitz
import pytesseract
from PIL import Image, ImageOps
from pywebpush import WebPushException, webpush

app = Flask(__name__)

# Use a persistent secret in production. A safe temporary value keeps local
# development working, but intentionally signs everyone out after a restart.
configured_secret = os.environ.get("FLASK_SECRET_KEY")
if not configured_secret:
    configured_secret = secrets.token_urlsafe(48)
    print("WARNING: FLASK_SECRET_KEY is not set; sessions will reset when the app restarts.")
app.secret_key = configured_secret
CERTIFICATE_MAX_FILE_SIZE = 10 * 1024 * 1024
PROFILE_PHOTO_MAX_FILE_SIZE = 5 * 1024 * 1024
# Leave room for multipart form data while enforcing the per-file checks below.
app.config["MAX_CONTENT_LENGTH"] = CERTIFICATE_MAX_FILE_SIZE + (1 * 1024 * 1024)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE") == "1",
)
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "").rstrip("/")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.environ.get("VAPID_SUBJECT", "mailto:admin@example.com")

bcrypt = Bcrypt(app)

PASSWORD_REQUIREMENTS_MESSAGE = "Use a password with at least 8 characters."
SECURITY_QUESTION_OPTIONS = (
    "What was the name of your school?",
    "What do people call you?",
    "What is your favorite animal?",
    "What is your favorite color?"
)
ONBOARDING_DEMO_CARDS = (
    {"id": "python-uiux", "name": "Aarav", "teach_skill": "Python Programming", "learn_skill": "UI/UX Design", "level": "Intermediate", "availability": "Weekday evenings", "bio": "Build useful projects and design friendlier experiences."},
    {"id": "web-content", "name": "Mira", "teach_skill": "Web Development", "learn_skill": "Content Writing", "level": "Beginner", "availability": "Weekends", "bio": "Turn clear ideas into websites people enjoy using."},
    {"id": "excel-marketing", "name": "Kabir", "teach_skill": "Excel & Data Analysis", "learn_skill": "Digital Marketing", "level": "Intermediate", "availability": "Weekday mornings", "bio": "Find the story in data, then help people see it."},
    {"id": "public-graphic", "name": "Ananya", "teach_skill": "Public Speaking", "learn_skill": "Graphic Design", "level": "Beginner", "availability": "Weekday afternoons", "bio": "Practice confident presentations with creative visual storytelling."},
    {"id": "photoshop-finance", "name": "Rohan", "teach_skill": "Adobe Photoshop", "learn_skill": "Personal Finance", "level": "Advanced", "availability": "Weekend mornings", "bio": "Create bold visuals while learning smarter money habits."},
    {"id": "sql-video", "name": "Sana", "teach_skill": "SQL & Databases", "learn_skill": "Video Editing", "level": "Intermediate", "availability": "Weekday evenings", "bio": "Organize information and bring stories to life on screen."},
    {"id": "guitar-spanish", "name": "Vihaan", "teach_skill": "Guitar", "learn_skill": "Spanish", "level": "Beginner", "availability": "Weekend afternoons", "bio": "Swap a new chord progression for a useful conversation."},
    {"id": "photography-cyber", "name": "Isha", "teach_skill": "Photography", "learn_skill": "Cybersecurity Basics", "level": "Intermediate", "availability": "Flexible schedule", "bio": "Frame better photos and protect your online world."},
    {"id": "figma-javascript", "name": "Dev", "teach_skill": "Figma", "learn_skill": "JavaScript", "level": "Intermediate", "availability": "Weekday nights", "bio": "Prototype beautiful ideas, then make them interactive."},
    {"id": "cooking-data", "name": "Naina", "teach_skill": "Cooking Basics", "learn_skill": "Data Visualization", "level": "Beginner", "availability": "Weekend evenings", "bio": "Mix great flavours and turn numbers into clear stories."},
)
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 5
_failed_attempts = {}


def csrf_token():
    """Create one unpredictable CSRF token per browser session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def client_address():
    """Use Flask's client address; a production proxy should pass a trusted address."""
    return request.remote_addr or "unknown"


def login_attempt_key(scope):
    return f"{scope}:{client_address()}"


def login_is_rate_limited(scope):
    now = time.monotonic()
    key = login_attempt_key(scope)
    attempts = [attempt for attempt in _failed_attempts.get(key, []) if now - attempt < LOGIN_ATTEMPT_WINDOW_SECONDS]
    _failed_attempts[key] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(scope):
    key = login_attempt_key(scope)
    _failed_attempts[key] = [
        *[attempt for attempt in _failed_attempts.get(key, []) if time.monotonic() - attempt < LOGIN_ATTEMPT_WINDOW_SECONDS],
        time.monotonic(),
    ]


def clear_failed_logins(scope):
    _failed_attempts.pop(login_attempt_key(scope), None)


def notification_preferences_for(user):
    """Return safe notification preferences for both new and legacy accounts."""
    preferences = user.get("notification_preferences") if user else None
    return preferences if isinstance(preferences, dict) else {}


@app.context_processor
def inject_security_question_options():
    return {
        "security_question_options": SECURITY_QUESTION_OPTIONS,
        "csrf_token": csrf_token(),
        "push_vapid_public_key": VAPID_PUBLIC_KEY,
    }


@app.before_request
def protect_post_requests():
    """Require a same-session CSRF token for every state-changing browser form."""
    if request.method != "POST":
        return None
    submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected_token = session.get("_csrf_token")
    if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
        abort(400, description="Your form session expired. Refresh the page and try again.")


def has_valid_password(password):
    """Keep account passwords simple while requiring a minimum usable length."""
    return len(password) >= 8


def normalize_security_answer(answer):
    """Compare security answers consistently without storing their plain text."""
    return re.sub(r"[^a-z0-9]+", "", answer.strip().lower())


def create_security_questions(form):
    """Validate and hash the two recovery answers supplied during account setup."""
    first_question = form.get("security_question_one", "")
    second_question = form.get("security_question_two", "")
    first_answer = normalize_security_answer(form.get("security_answer_one", ""))
    second_answer = normalize_security_answer(form.get("security_answer_two", ""))

    if first_question not in SECURITY_QUESTION_OPTIONS or second_question not in SECURITY_QUESTION_OPTIONS:
        return None, "Please choose both security questions."
    if first_question == second_question:
        return None, "Choose two different security questions."
    if not first_answer or not second_answer:
        return None, "Please answer both security questions."

    return [
        {
            "question": first_question,
            "answer_hash": bcrypt.generate_password_hash(first_answer).decode("utf-8")
        },
        {
            "question": second_question,
            "answer_hash": bcrypt.generate_password_hash(second_answer).decode("utf-8")
        }
    ], None


def has_complete_security_questions(account):
    questions = account.get("security_questions", []) if account else []
    return len(questions) == 2 and all(
        question.get("question") in SECURITY_QUESTION_OPTIONS and question.get("answer_hash")
        for question in questions
    )

CERTIFICATE_UPLOAD_FOLDER = Path(app.root_path) / "uploads" / "certificates"
CERTIFICATE_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
PROFILE_PHOTO_UPLOAD_FOLDER = Path(app.root_path) / "uploads" / "profile_photos"
PROFILE_PHOTO_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_CERTIFICATE_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
ALLOWED_PROFILE_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg"}
WEEKDAYS = [
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
]
DURATION_WEEKS = {"1 Month": 4, "3 Months": 12, "6 Months": 24}
TESSERACT_PATHS = (
    os.environ.get("TESSERACT_CMD", ""),
    shutil.which("tesseract") or "",
    "/opt/homebrew/bin/tesseract",
    "/usr/local/bin/tesseract",
)
for tesseract_path in TESSERACT_PATHS:
    if tesseract_path and Path(tesseract_path).is_file():
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
        break


@app.errorhandler(413)
def certificate_too_large(_error):
    return render_template(
        "upload_error.html",
        error="The uploaded file is too large. Please upload a certificate no larger than 10 MB."
    ), 413


SKILL_QUESTIONS = {
    "web development": [
        {
            "question": "What is HTML mainly used for?",
            "options": ["Structuring web content", "Storing passwords", "Editing images", "Running MongoDB"],
            "answer": "Structuring web content"
        },
        {
            "question": "Which CSS property changes text colour?",
            "options": ["font-style", "background", "color", "display"],
            "answer": "color"
        },
        {
            "question": "What is JavaScript commonly used for in a webpage?",
            "options": ["Adding interactivity", "Creating database tables", "Installing Python", "Compressing images"],
            "answer": "Adding interactivity"
        },
        {
            "question": "What is Flask?",
            "options": ["A Python web framework", "A CSS library", "A database", "A web browser"],
            "answer": "A Python web framework"
        },
        {
            "question": "Which HTTP status code usually means a request succeeded?",
            "options": ["200", "404", "500", "403"],
            "answer": "200"
        },
        {
            "question": "Which HTML element represents the main content of a page?",
            "options": ["<main>", "<meta>", "<style>", "<link>"],
            "answer": "<main>"
        },
        {
            "question": "What does the viewport meta tag help with?",
            "options": ["Responsive mobile layout", "Database security", "Password hashing", "Python imports"],
            "answer": "Responsive mobile layout"
        },
        {
            "question": "Which CSS layout system is useful for arranging items in one direction?",
            "options": ["Flexbox", "Cookies", "MongoDB", "Jinja"],
            "answer": "Flexbox"
        },
        {
            "question": "Which HTTP method is normally used to submit form data that changes information?",
            "options": ["POST", "GET", "HEAD", "TRACE"],
            "answer": "POST"
        },
        {
            "question": "What does DOM stand for?",
            "options": ["Document Object Model", "Data Output Method", "Digital Object Map", "Document Order Mode"],
            "answer": "Document Object Model"
        },
        {
            "question": "What is included in the CSS box model?",
            "options": ["Content, padding, border, and margin", "Only width and height", "Routes and templates", "Tables and documents"],
            "answer": "Content, padding, border, and margin"
        },
        {
            "question": "Which CSS feature applies styles at different screen sizes?",
            "options": ["Media queries", "Sessions", "Indexes", "Decorators"],
            "answer": "Media queries"
        },
        {
            "question": "What does HTTP status 404 mean?",
            "options": ["Resource not found", "Request succeeded", "Server started", "User authenticated"],
            "answer": "Resource not found"
        },
        {
            "question": "What is Jinja used for in Flask?",
            "options": ["Rendering HTML templates", "Hashing passwords", "Installing MongoDB", "Compiling CSS"],
            "answer": "Rendering HTML templates"
        },
        {
            "question": "Why should passwords be hashed?",
            "options": ["To avoid storing plain-text passwords", "To make pages responsive", "To create routes", "To style forms"],
            "answer": "To avoid storing plain-text passwords"
        },
        {
            "question": "How does MongoDB usually store one record?",
            "options": ["As a document", "As a CSS rule", "As an HTML tag", "As a Python package"],
            "answer": "As a document"
        },
        {
            "question": "What does a Flask route connect?",
            "options": ["A URL to a Python function", "CSS to MongoDB", "HTML to a password", "An image to a terminal"],
            "answer": "A URL to a Python function"
        },
        {
            "question": "What helps prevent injected HTML from being rendered in Jinja templates?",
            "options": ["Automatic escaping", "Media queries", "Flexbox", "Browser history"],
            "answer": "Automatic escaping"
        },
        {
            "question": "Which CSS system is designed for rows and columns?",
            "options": ["CSS Grid", "Flask sessions", "PyMongo", "bcrypt"],
            "answer": "CSS Grid"
        },
        {
            "question": "Which decorator commonly defines a Flask URL?",
            "options": ["@app.route", "@css.grid", "@mongo.find", "@html.page"],
            "answer": "@app.route"
        }
    ],
    "python": [
        {
            "question": "Which keyword defines a function in Python?",
            "options": ["func", "define", "def", "function"],
            "answer": "def"
        },
        {
            "question": "Which brackets create a Python list?",
            "options": ["[]", "{}", "()", "<>"],
            "answer": "[]"
        },
        {
            "question": "Which function returns the length of a value?",
            "options": ["size()", "count()", "length()", "len()"],
            "answer": "len()"
        },
        {
            "question": "Which operator compares two values for equality?",
            "options": ["=", "==", "!=", ":="],
            "answer": "=="
        },
        {
            "question": "Why is indentation important in Python?",
            "options": ["It defines code blocks", "It changes variable types", "It installs packages", "It creates comments"],
            "answer": "It defines code blocks"
        },
        {
            "question": "Which structure stores key-value pairs?",
            "options": ["Dictionary", "List", "Tuple", "String"],
            "answer": "Dictionary"
        },
        {
            "question": "Which keyword starts a loop over a collection?",
            "options": ["for", "loop", "each", "repeat"],
            "answer": "for"
        },
        {
            "question": "Which block handles an exception?",
            "options": ["try/except", "if/else", "for/in", "def/return"],
            "answer": "try/except"
        },
        {
            "question": "Which keyword loads a Python module?",
            "options": ["import", "include", "require", "using"],
            "answer": "import"
        },
        {
            "question": "Which keyword creates a class?",
            "options": ["class", "object", "type", "model"],
            "answer": "class"
        },
        {
            "question": "Which list method adds one item to the end?",
            "options": ["append()", "add()", "push()", "insert_end()"],
            "answer": "append()"
        },
        {
            "question": "Which operator requires both conditions to be true?",
            "options": ["and", "or", "not", "in"],
            "answer": "and"
        },
        {
            "question": "Which value represents the absence of a value?",
            "options": ["None", "null", "empty", "undefined"],
            "answer": "None"
        },
        {
            "question": "What is a list comprehension used for?",
            "options": ["Creating a list from an expression", "Installing a package", "Opening a server", "Defining CSS"],
            "answer": "Creating a list from an expression"
        },
        {
            "question": "What is pip commonly used for?",
            "options": ["Installing Python packages", "Styling HTML", "Creating databases", "Running JavaScript"],
            "answer": "Installing Python packages"
        },
        {
            "question": "Why use a Python virtual environment?",
            "options": ["To isolate project packages", "To design a logo", "To replace MongoDB", "To create HTML tags"],
            "answer": "To isolate project packages"
        },
        {
            "question": "What does range(3) produce for a loop?",
            "options": ["0, 1, 2", "1, 2, 3", "0, 1, 2, 3", "3 only"],
            "answer": "0, 1, 2"
        },
        {
            "question": "What does return do inside a function?",
            "options": ["Sends a result back", "Repeats the function", "Imports a module", "Creates a class"],
            "answer": "Sends a result back"
        },
        {
            "question": "What begins an f-string?",
            "options": ["f before the quote", "$ before the quote", "# before the quote", "@ before the quote"],
            "answer": "f before the quote"
        },
        {
            "question": "Which PyMongo method returns one matching document?",
            "options": ["find_one()", "select_one()", "get_row()", "fetch_first()"],
            "answer": "find_one()"
        }
    ],
    "ui/ux": [
        {
            "question": "What is a wireframe?",
            "options": ["A basic layout plan", "A final database", "A colour format", "A programming language"],
            "answer": "A basic layout plan"
        },
        {
            "question": "What does UX focus on?",
            "options": ["The user's overall experience", "Only logo colours", "Server installation", "File compression"],
            "answer": "The user's overall experience"
        },
        {
            "question": "Why is colour contrast important?",
            "options": ["It improves readability", "It stores data", "It speeds up Python", "It creates routes"],
            "answer": "It improves readability"
        },
        {
            "question": "What is the purpose of user testing?",
            "options": ["Find usability problems", "Choose a database", "Install Flask", "Hash passwords"],
            "answer": "Find usability problems"
        },
        {
            "question": "Why should interfaces stay visually consistent?",
            "options": ["They become easier to understand", "They use more storage", "They remove navigation", "They avoid all testing"],
            "answer": "They become easier to understand"
        },
        {
            "question": "What is a prototype used for?",
            "options": ["Testing an interaction before final development", "Storing passwords", "Running a database", "Compressing files"],
            "answer": "Testing an interaction before final development"
        },
        {
            "question": "What is a user persona?",
            "options": ["A research-based user representation", "A CSS property", "A database record type", "A server route"],
            "answer": "A research-based user representation"
        },
        {
            "question": "What does visual hierarchy help users understand?",
            "options": ["What is most important", "How to install Python", "Where data is stored", "How passwords are hashed"],
            "answer": "What is most important"
        },
        {
            "question": "What does accessible design aim to do?",
            "options": ["Include people with different abilities", "Use only one colour", "Remove all labels", "Avoid mobile devices"],
            "answer": "Include people with different abilities"
        },
        {
            "question": "What is a call-to-action?",
            "options": ["A prompt encouraging the next user action", "A database query", "A colour palette", "A font file"],
            "answer": "A prompt encouraging the next user action"
        },
        {
            "question": "Why is whitespace useful in a layout?",
            "options": ["It improves clarity and grouping", "It stores more data", "It encrypts passwords", "It replaces navigation"],
            "answer": "It improves clarity and grouping"
        },
        {
            "question": "What does responsive design support?",
            "options": ["Different screen sizes", "Only desktop screens", "Only printed pages", "Only database forms"],
            "answer": "Different screen sizes"
        },
        {
            "question": "What is a usability heuristic?",
            "options": ["A general rule for evaluating interfaces", "A Python package", "A database password", "A file format"],
            "answer": "A general rule for evaluating interfaces"
        },
        {
            "question": "What is an affordance in interface design?",
            "options": ["A clue about how an element can be used", "A server error", "A database collection", "A screen resolution"],
            "answer": "A clue about how an element can be used"
        },
        {
            "question": "What does a user journey map show?",
            "options": ["Steps and experiences across a task", "CSS selectors", "Database indexes", "Python imports"],
            "answer": "Steps and experiences across a task"
        },
        {
            "question": "What does an A/B test compare?",
            "options": ["Two design variations", "Two databases", "Two passwords", "Two programming languages"],
            "answer": "Two design variations"
        },
        {
            "question": "Why should meaningful images have alt text?",
            "options": ["To support screen-reader users", "To speed up MongoDB", "To create sessions", "To define a route"],
            "answer": "To support screen-reader users"
        },
        {
            "question": "What should happen after a user submits a form?",
            "options": ["The interface should provide feedback", "The page should stay unclear", "All navigation should disappear", "The font should change randomly"],
            "answer": "The interface should provide feedback"
        },
        {
            "question": "Which is a useful usability measurement?",
            "options": ["Task completion rate", "Number of CSS files", "Password length only", "Database name"],
            "answer": "Task completion rate"
        },
        {
            "question": "Why keep button styles consistent?",
            "options": ["Users can recognise available actions", "It creates database records", "It installs frameworks", "It removes accessibility"],
            "answer": "Users can recognise available actions"
        }
    ]
}


def normalise_skill(skill):
    """Make skill comparisons ignore capital letters and extra spaces."""
    return skill.strip().lower()


def requires_skill_verification(user):
    """Intermediate and Advanced users must prove and verify their skill."""
    return user.get("skill_level") in ["Intermediate", "Advanced"]


def is_skill_verified(user):
    """Check that verification still matches the user's current skill and level."""
    verification = user.get("verification")

    return bool(
        verification
        and verification.get("passed")
        and normalise_skill(verification.get("skill", ""))
        == normalise_skill(user.get("teach_skill", ""))
        and verification.get("skill_level") == user.get("skill_level")
    )


def is_user_ready_to_exchange(user):
    """Beginners can exchange directly; higher levels must be verified."""
    return not requires_skill_verification(user) or is_skill_verified(user)


def certificate_file_is_allowed(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_CERTIFICATE_EXTENSIONS
    )


def certificate_file_size_is_allowed(certificate_file):
    """Check one certificate's size without consuming its upload stream."""
    certificate_file.stream.seek(0, os.SEEK_END)
    size = certificate_file.stream.tell()
    certificate_file.stream.seek(0)
    return size <= CERTIFICATE_MAX_FILE_SIZE


def profile_photo_file_size_is_allowed(photo_file):
    photo_file.stream.seek(0, os.SEEK_END)
    size = photo_file.stream.tell()
    photo_file.stream.seek(0)
    return size <= PROFILE_PHOTO_MAX_FILE_SIZE


def certificate_file_content_is_valid(certificate_file):
    """Reject a renamed file that is not really the selected certificate format."""
    extension = certificate_file.filename.rsplit(".", 1)[1].lower()
    try:
        if extension == "pdf":
            certificate_file.stream.seek(0)
            is_pdf = certificate_file.stream.read(5) == b"%PDF-"
            certificate_file.stream.seek(0)
            return is_pdf

        certificate_file.stream.seek(0)
        with Image.open(certificate_file.stream) as image:
            image.verify()
        certificate_file.stream.seek(0)
        return True
    except Exception:
        certificate_file.stream.seek(0)
        return False


def save_certificate_file(certificate_file):
    """Save an uploaded certificate with a safe, unique filename."""
    original_name = secure_filename(certificate_file.filename)
    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid4().hex}.{extension}"
    certificate_file.save(CERTIFICATE_UPLOAD_FOLDER / stored_name)

    return {
        "filename": stored_name,
        "original_name": original_name,
        "uploaded_at": datetime.now(timezone.utc)
    }


def normalise_certificate_text(value):
    """Prepare OCR text and profile values for conservative comparisons."""
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(character for character in value if not unicodedata.combining(character))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", value.lower())).strip()


def certificate_skill_terms(skill):
    """Return safe textual alternatives for common skill labels."""
    normalised = normalise_certificate_text(skill)
    aliases = {
        "python programming": ("python programming", "python"),
        "ui ux": ("ui ux", "user interface", "user experience"),
        "web development": ("web development", "web developer"),
        "data analysis": ("data analysis", "data analytics"),
        "graphic design": ("graphic design",),
        "social media marketing": ("social media marketing",),
    }
    return aliases.get(normalised, (normalised,))


def text_contains_phrase(text, phrase):
    """Match complete words only, avoiding a partial match inside another word."""
    if not phrase or len(phrase) < 2:
        return False
    return f" {phrase} " in f" {text} "


def extract_certificate_text(certificate_path, extension):
    """Read text from a digital PDF or OCR a JPG, JPEG, PNG, or scanned PDF."""
    try:
        if extension == "pdf":
            document = fitz.open(certificate_path)
            try:
                page_text = "\n".join(page.get_text("text") for page in document)
                if len(page_text.strip()) >= 30:
                    return page_text, "PDF text", ""

                # A scanned certificate has no embedded text, so OCR up to two pages.
                ocr_pages = []
                for page in list(document)[:2]:
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    with Image.open(BytesIO(pixmap.tobytes("png"))) as image:
                        ocr_pages.append(pytesseract.image_to_string(image))
                return "\n".join(ocr_pages), "PDF OCR", ""
            finally:
                document.close()

        with Image.open(certificate_path) as opened_image:
            image = ImageOps.exif_transpose(opened_image).convert("RGB")
            if image.width * image.height > 30_000_000:
                return "", "", "The image is too large to analyse safely."
            return pytesseract.image_to_string(image), "Image OCR", ""
    except Exception as error:
        return "", "", f"Could not read certificate text: {str(error)[:180]}"


def certificate_trust_signals(extracted_text):
    """Collect issuer and reference clues for an administrator to inspect."""
    lower_text = extracted_text.lower()
    issuer_names = {
        "coursera": "Coursera", "udemy": "Udemy", "edx": "edX",
        "linkedin learning": "LinkedIn Learning", "google": "Google",
        "microsoft": "Microsoft", "ibm": "IBM", "aws": "AWS",
        "oracle": "Oracle", "nptel": "NPTEL",
    }
    issuer = next((label for key, label in issuer_names.items() if key in lower_text), "")
    identifier_match = re.search(
        r"(?:certificate|credential)\s*(?:id|no|number)?\s*[:#-]?\s*([a-z0-9-]{5,})",
        lower_text,
    )
    links = re.findall(r"https?://[^\s<>()]+", extracted_text, flags=re.IGNORECASE)
    return {
        "issuer": issuer,
        "certificate_id": identifier_match.group(1).upper() if identifier_match else "",
        "verification_link": links[0][:250] if links else "",
        "qr_reference_found": bool(re.search(r"\bqr\s*(?:code)?\b|scan to verify", lower_text)),
    }


def analyse_certificate(certificate_proof, profile):
    """Choose auto-verify, admin review, or auto-reject from certificate text."""
    certificate_path = CERTIFICATE_UPLOAD_FOLDER / certificate_proof["filename"]
    extension = certificate_proof["filename"].rsplit(".", 1)[1].lower()
    extracted_text, extraction_method, extraction_error = extract_certificate_text(
        certificate_path, extension
    )
    normalised_text = normalise_certificate_text(extracted_text)
    expected_name = normalise_certificate_text(profile.get("name"))
    expected_skill = normalise_certificate_text(profile.get("teach_skill"))
    expected_level = normalise_certificate_text(profile.get("skill_level"))
    matches = {
        "name": text_contains_phrase(normalised_text, expected_name),
        "skill": any(
            text_contains_phrase(normalised_text, term)
            for term in certificate_skill_terms(profile.get("teach_skill", ""))
        ),
        "level": text_contains_phrase(normalised_text, expected_level),
    }
    trust_signals = certificate_trust_signals(extracted_text)
    has_reference = bool(
        trust_signals["issuer"]
        or trust_signals["certificate_id"]
        or trust_signals["verification_link"]
    )
    readable_text = len(normalised_text) >= 30 and not extraction_error

    if readable_text and all(matches.values()) and has_reference:
        status = "auto_verified"
        reason = "The certificate name, teaching skill, and level match the profile."
    elif readable_text and all(matches.values()):
        status = "pending"
        reason = (
            "The certificate details match the profile, but an administrator must confirm "
            "the issuer or certificate reference."
        )
    elif readable_text and not any(matches.values()):
        status = "rejected"
        reason = "The certificate text does not match the profile name, teaching skill, or level."
    else:
        status = "pending"
        reason = (
            "The certificate needs administrator review because one or more details "
            "are missing, unclear, or do not match the profile."
        )

    certificate_proof["analysis"] = {
        "method": extraction_method or "Not available",
        "text_found": bool(normalised_text),
        "character_count": len(extracted_text.strip()),
        "preview": extracted_text.strip()[:700],
        "error": extraction_error,
        "matches": matches,
        "trust_signals": trust_signals,
        "decision": status,
        "analysed_at": datetime.now(timezone.utc),
    }
    return {
        "status": status,
        "reason": reason,
        "automated": True,
        "reviewed_at": datetime.now(timezone.utc) if status != "pending" else None,
    }


def make_skill_verification(user):
    """Create the standard verification record for an automatic or admin approval."""
    return {
        "skill": user.get("teach_skill"),
        "skill_level": user.get("skill_level"),
        "passed": True,
        "verified_at": datetime.now(timezone.utc),
        "verification_method": "certificate_text_match",
        "certificate_id": f"SS-{str(user['_id'])[-8:].upper()}-{datetime.now(timezone.utc).year}",
    }


def delete_uploaded_file(folder, filename):
    """Remove one owned upload while preventing a filename from escaping its folder."""
    if not filename:
        return
    candidate = folder / Path(filename).name
    if candidate.is_file():
        candidate.unlink()


def profile_photo_file_is_allowed(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_PROFILE_PHOTO_EXTENSIONS
    )


def save_profile_photo(photo_file):
    """Save an optional profile photo with a safe, unique filename."""
    original_name = secure_filename(photo_file.filename)
    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid4().hex}.{extension}"
    photo_file.save(PROFILE_PHOTO_UPLOAD_FOLDER / stored_name)
    return stored_name


def notification_url(link):
    if not link:
        return PUBLIC_APP_URL or "/notifications"
    if link.startswith("http://") or link.startswith("https://"):
        return link
    return f"{PUBLIC_APP_URL}{link}" if PUBLIC_APP_URL else link


def send_notification_email(user, message, link):
    """Send opt-in email through configured SMTP, without failing the app on errors."""
    if not all((PUBLIC_APP_URL, SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, user.get("email"))):
        return False
    email = EmailMessage()
    email["Subject"] = "SkillSwap notification"
    email["From"] = SMTP_FROM
    email["To"] = user["email"]
    email.set_content(f"{message}\n\nOpen SkillSwap: {notification_url(link)}")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(email)
        return True
    except (OSError, smtplib.SMTPException):
        return False


def send_browser_push(user, message, link):
    """Deliver a Web Push message to opted-in browsers when VAPID is configured."""
    if not (VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY):
        return
    subscriptions = user.get("push_subscriptions", [])
    expired_endpoints = []
    payload = json.dumps({
        "title": "SkillSwap",
        "body": message,
        "url": notification_url(link),
    })
    for subscription in subscriptions:
        try:
            webpush(
                subscription_info=subscription,
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={"sub": VAPID_SUBJECT},
            )
        except WebPushException as error:
            response = getattr(error, "response", None)
            if getattr(response, "status_code", None) in {404, 410}:
                expired_endpoints.append(subscription.get("endpoint"))
        except (OSError, ValueError):
            pass
    if expired_endpoints:
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$pull": {"push_subscriptions": {"endpoint": {"$in": expired_endpoints}}}},
        )


def deliver_notification(user_id, message, link):
    """Send opted-in delivery channels after the in-app notification is stored."""
    user = users_collection.find_one({"_id": user_id})
    if not user:
        return
    preferences = notification_preferences_for(user)
    if preferences.get("email"):
        send_notification_email(user, message, link)
    if preferences.get("push"):
        send_browser_push(user, message, link)


def add_notification(user_id, message, link=None, notification_type=None):
    """Store an in-app notification and send any delivery channels the user enabled."""
    notification = {
        "user_id": user_id,
        "message": message[:300],
        "link": link,
        "is_read": False,
        "created_at": datetime.now(timezone.utc)
    }
    if notification_type:
        notification["type"] = notification_type
    notifications_collection.insert_one(notification)
    deliver_notification(user_id, notification["message"], link)


def add_activity(user_id, title, detail="", link=None):
    """Save a visible record of an important SkillSwap action."""
    activities_collection.insert_one({
        "user_id": user_id,
        "title": title[:120],
        "detail": detail[:300],
        "link": link,
        "created_at": datetime.now(timezone.utc)
    })


def session_end_time(session_date, start_time, duration_minutes):
    """Return a local end time for a planned SkillSwap session."""
    try:
        start = datetime.strptime(
            f"{session_date} {start_time}", "%Y-%m-%d %H:%M"
        )
        return start + timedelta(minutes=int(duration_minutes))
    except (TypeError, ValueError):
        return None


def create_due_session_rating_reminders():
    """Create one in-app rating reminder per participant after a session ends.

    A reminder is created only once for each planned session. The server checks
    this whenever a signed-in learner opens or uses SkillSwap.
    """
    now = datetime.now()
    today_date = now.date().isoformat()
    today_name = now.strftime("%A")

    for connection in matches_collection.find({
        "action": "interested",
        "status": "accepted"
    }):
        if not timetable_is_confirmed(connection):
            continue

        for slot in connection.get("timetable", []):
            if today_name not in slot.get("days", []):
                continue

            end_time = session_end_time(
                today_date,
                slot.get("start_time"),
                slot.get("duration_minutes")
            )
            if not end_time or now < end_time:
                continue

            teacher_id = slot.get("teacher_id")
            if not teacher_id:
                continue

            session_key = {
                "connection_id": connection["_id"],
                "teacher_id": teacher_id,
                "session_date": today_date,
                "start_time": slot.get("start_time", "")
            }
            sessions_collection.update_one(
                session_key,
                {"$setOnInsert": {
                    **session_key,
                    "skill": slot.get("skill", "Skill exchange"),
                    "start_time": slot.get("start_time", ""),
                    "duration_minutes": slot.get("duration_minutes", 60),
                    "status": "rating_open",
                    "created_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            scheduled_session = sessions_collection.find_one(session_key)

            claimed = sessions_collection.update_one(
                {
                    "_id": scheduled_session["_id"],
                    "rating_reminders_sent_at": {"$exists": False}
                },
                {"$set": {"rating_reminders_sent_at": datetime.now(timezone.utc)}}
            )
            if not claimed.modified_count:
                continue

            teacher = users_collection.find_one({"_id": teacher_id})
            learner_id = (
                connection["to_user_id"]
                if connection["from_user_id"] == teacher_id
                else connection["from_user_id"]
            )
            learner = users_collection.find_one({"_id": learner_id})
            if not teacher or not learner:
                continue

            rate_link = url_for("rate_session", session_id=scheduled_session["_id"])
            add_notification(
                learner_id,
                f"Your {slot.get('skill', 'SkillSwap')} session with {teacher['name']} has ended. How was your experience? Rate {teacher['name']}.",
                rate_link,
                notification_type="session_rating"
            )


def admin_required(view):
    """Allow access only to accounts explicitly marked as administrators."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session or not ObjectId.is_valid(session["user_id"]):
            return redirect(url_for("admin_login"))
        admin = users_collection.find_one({
            "_id": ObjectId(session["user_id"]),
            "role": "admin"
        })
        if not admin:
            session.clear()
            return redirect(url_for("admin_login"))
        if (
            not admin.get("admin_terms_accepted_at")
            and request.endpoint not in {"admin_terms", "accept_admin_terms"}
        ):
            return redirect(url_for("admin_terms"))
        return view(*args, **kwargs)
    return wrapped_view


def suspension_is_active(user):
    """Return whether a learner is currently suspended, expiring after seven days."""
    if not user or user.get("role") == "admin" or not user.get("is_suspended"):
        return False

    now = datetime.now(timezone.utc)
    suspended_until = user.get("suspended_until")
    if suspended_until is None:
        # Give legacy suspensions the same seven-day limit as new suspensions.
        suspended_until = now + timedelta(days=7)
        user["suspended_until"] = suspended_until
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"suspended_until": suspended_until}}
        )
    elif suspended_until.tzinfo is None:
        suspended_until = suspended_until.replace(tzinfo=timezone.utc)

    if suspended_until <= now:
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_suspended": False}, "$unset": {"suspended_until": ""}}
        )
        return False
    user["suspended_until"] = suspended_until
    return True


@app.before_request
def block_suspended_users():
    """End a normal user's session when an admin has suspended their account."""
    if request.endpoint in {
        "static", "splash", "home", "access_choice", "login", "register",
        "admin_login", "admin_setup", "forgot_password", "reset_password", "logout",
        "terms", "accept_terms"
    }:
        return None

    user_id = session.get("user_id")
    if not user_id or not ObjectId.is_valid(user_id):
        return None

    account = users_collection.find_one({"_id": ObjectId(user_id)})
    if account and account.get("role") != "admin" and suspension_is_active(account):
        session.clear()
        return redirect(url_for("login", suspended="1"))

    if account and account.get("role") != "admin":
        create_due_session_rating_reminders()

    return None


@app.context_processor
def global_navigation_data():
    """Provide the unread notification count to the signed-in navigation bar."""
    if "user_id" not in session or not ObjectId.is_valid(session["user_id"]):
        return {"unread_notification_count": 0}

    return {
        "unread_notification_count": notifications_collection.count_documents({
            "user_id": ObjectId(session["user_id"]),
            "is_read": False
        })
    }


def has_matching_certificate(user):
    """Check that the uploaded proof belongs to the current skill and level."""
    certificate = user.get("certificate_proof")

    return bool(
        certificate
        and normalise_skill(certificate.get("skill", ""))
        == normalise_skill(user.get("teach_skill", ""))
        and certificate.get("skill_level") == user.get("skill_level")
    )


def get_timetable_slot(connection, teacher_id):
    """Return the timetable entry owned by one teaching partner."""
    for slot in connection.get("timetable", []):
        if slot.get("teacher_id") == teacher_id:
            return slot
    return None


def timetable_is_ready(connection):
    """A timetable needs one teaching slot from each exchange partner."""
    timetable = connection.get("timetable", [])
    teacher_ids = {slot.get("teacher_id") for slot in timetable}
    return (
        len(timetable) == 2
        and connection.get("from_user_id") in teacher_ids
        and connection.get("to_user_id") in teacher_ids
    )


def timetable_is_confirmed(connection):
    """Both exchange partners must confirm the complete shared timetable."""
    confirmations = set(connection.get("timetable_confirmed_by", []))
    return timetable_is_ready(connection) and {
        connection.get("from_user_id"), connection.get("to_user_id")
    }.issubset(confirmations)


def get_exchange_progress(connection, current_user):
    """Calculate visible progress from mutually confirmed sessions."""
    confirmed_sessions = sessions_collection.count_documents({
        "connection_id": connection["_id"],
        "status": "confirmed"
    })
    weekly_sessions = sum(
        len(slot.get("days", [])) for slot in connection.get("timetable", [])
    )
    planned_sessions = weekly_sessions * DURATION_WEEKS.get(
        current_user.get("learning_duration"), 0
    )
    percentage = (
        min(round((confirmed_sessions / planned_sessions) * 100), 100)
        if planned_sessions else 0
    )

    return {
        "confirmed_sessions": confirmed_sessions,
        "planned_sessions": planned_sessions,
        "percentage": percentage,
        "weekly_sessions": weekly_sessions
    }


def get_exchange_goal(connection, user_id):
    """Return one partner's personal goal for an exchange."""
    for goal in connection.get("exchange_goals", []):
        if goal.get("user_id") == user_id:
            return goal
    return None


def get_user_consistency_streak(user_id):
    """Return consecutive weeks, including this one, with a confirmed session."""
    connection_ids = [
        connection["_id"]
        for connection in matches_collection.find({
            "action": "interested",
            "status": {"$in": ["accepted", "completed"]},
            "$or": [{"from_user_id": user_id}, {"to_user_id": user_id}]
        }, {"_id": 1})
    ]

    if not connection_ids:
        return 0

    weekly_activity = set()
    for completed_session in sessions_collection.find({
        "connection_id": {"$in": connection_ids},
        "status": "confirmed"
    }, {"session_date": 1}):
        try:
            session_day = datetime.fromisoformat(
                completed_session["session_date"]
            ).date()
        except (KeyError, ValueError):
            continue
        weekly_activity.add(session_day - timedelta(days=session_day.weekday()))

    current_week = datetime.now().date() - timedelta(
        days=datetime.now().weekday()
    )
    streak = 0
    while current_week in weekly_activity:
        streak += 1
        current_week -= timedelta(days=7)

    return streak


def get_weekly_leaderboard():
    """Rank users by confirmed teaching and learning sessions this week."""
    today = datetime.now().date()
    week_start = today - timedelta(days=today.weekday())
    week_end = week_start + timedelta(days=6)
    entries = {}
    connection_cache = {}

    for completed_session in sessions_collection.find({
        "status": "confirmed",
        "session_date": {"$gte": week_start.isoformat(), "$lte": week_end.isoformat()}
    }):
        connection_id = completed_session["connection_id"]
        if connection_id not in connection_cache:
            connection_cache[connection_id] = matches_collection.find_one({
                "_id": connection_id
            })
        connection = connection_cache[connection_id]
        if not connection:
            continue

        for user_id in [connection["from_user_id"], connection["to_user_id"]]:
            user = users_collection.find_one({"_id": user_id})
            if not user:
                continue
            entry = entries.setdefault(user_id, {
                "user": user,
                "teaching_sessions": 0,
                "learning_sessions": 0,
                "total_sessions": 0,
                "streak": 0,
                "labels": []
            })
            entry["total_sessions"] += 1
            if user_id == completed_session["teacher_id"]:
                entry["teaching_sessions"] += 1
            else:
                entry["learning_sessions"] += 1

    leaderboard = list(entries.values())
    for entry in leaderboard:
        entry["streak"] = get_user_consistency_streak(entry["user"]["_id"])

    if leaderboard:
        top_mentor = max(leaderboard, key=lambda entry: entry["teaching_sessions"])
        top_learner = max(leaderboard, key=lambda entry: entry["learning_sessions"])
        most_consistent = max(leaderboard, key=lambda entry: entry["streak"])
        if top_mentor["teaching_sessions"]:
            top_mentor["labels"].append("Top Mentor")
        if top_learner["learning_sessions"]:
            top_learner["labels"].append("Top Learner")
        if most_consistent["streak"]:
            most_consistent["labels"].append("Most Consistent")

    return sorted(
        leaderboard,
        key=lambda entry: (
            entry["total_sessions"],
            entry["teaching_sessions"],
            entry["learning_sessions"]
        ),
        reverse=True
    ), week_start, week_end


def calculate_compatibility(current_user, candidate):
    """Calculate a simple, beginner-friendly compatibility score out of 100."""
    score = 60  # The two users have complementary teach-and-learn skills.

    same_availability = (
        normalise_skill(current_user.get("availability", ""))
        == normalise_skill(candidate.get("availability", ""))
    )

    if same_availability:
        score += 20

    levels = {"Beginner": 1, "Intermediate": 2, "Advanced": 3}
    current_level = levels.get(current_user.get("skill_level"), 0)
    candidate_level = levels.get(candidate.get("skill_level"), 0)
    level_difference = abs(current_level - candidate_level)

    if level_difference == 0:
        score += 20
        level_message = "Same skill level"
    elif level_difference == 1:
        score += 10
        level_message = "One level apart"
    else:
        level_message = "Different skill levels"

    availability_message = (
        "Availability aligns" if same_availability else "Check availability"
    )

    return score, availability_message, level_message


def get_user_reputation(user_id):
    """Return a user's average rating and total number of reviews."""
    reviews = list(reviews_collection.find({"reviewed_user_id": user_id}))

    if not reviews:
        return {"average": None, "count": 0}

    average = round(
        sum(review["rating"] for review in reviews) / len(reviews),
        1
    )

    return {"average": average, "count": len(reviews)}


def get_questions_for_skill(skill, skill_level):
    """Return the assessment questions supported for a teaching skill."""
    if skill_level not in ["Intermediate", "Advanced"]:
        return None

    skill_name = normalise_skill(skill)

    aliases = {
        "web dev": "web development",
        "website development": "web development",
        "ui ux": "ui/ux",
        "ux/ui": "ui/ux"
    }

    return SKILL_QUESTIONS.get(aliases.get(skill_name, skill_name))


def award_user_badges(user):
    """Award badges when a user reaches simple SkillSwap milestones."""
    earned_badges = []
    duration = user.get("learning_duration")

    # Remove this badge when the user changes to an unverified skill or level.
    if not is_skill_verified(user):
        badges_collection.delete_many({
            "user_id": user["_id"],
            "name": "Verified Mentor"
        })

    duration_badges = {
        "1 Month": ("Starter Journey", "Committed to a one-month learning journey."),
        "3 Months": ("Committed Learner", "Committed to a three-month learning journey."),
        "6 Months": ("Growth Champion", "Committed to a six-month learning journey.")
    }

    if duration in duration_badges:
        earned_badges.append(duration_badges[duration])

    verification = user.get("verification")
    if verification and is_skill_verified(user):
        earned_badges.append((
            "Verified Mentor",
            f"Verified their {verification['skill']} knowledge."
        ))

    completed_count = matches_collection.count_documents({
        "action": "interested",
        "status": "completed",
        "$or": [
            {"from_user_id": user["_id"]},
            {"to_user_id": user["_id"]}
        ]
    })
    if completed_count > 0:
        earned_badges.append((
            "Skill Exchanger",
            "Completed at least one two-way skill exchange."
        ))

    reputation = get_user_reputation(user["_id"])
    if reputation["count"] > 0 and reputation["average"] >= 4:
        earned_badges.append((
            "Trusted Partner",
            "Maintained an average rating of four stars or higher."
        ))

    for badge_name, badge_description in earned_badges:
        badges_collection.update_one(
            {"user_id": user["_id"], "name": badge_name},
            {
                "$setOnInsert": {
                    "user_id": user["_id"],
                    "name": badge_name,
                    "description": badge_description,
                    "earned_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )


def find_complementary_matches(current_user):
    """Return users whose teach and learn skills complement the current user."""
    matches = []
    if not current_user.get("teach_skill") or not current_user.get("learn_skill"):
        return matches
    handled_match_ids = {
        match["to_user_id"]
        for match in matches_collection.find(
            {
                "from_user_id": current_user["_id"],
                "status": {"$in": ["passed", "pending", "accepted", "rejected"]}
            },
            {"to_user_id": 1}
        )
    }

    for candidate in users_collection.find({
        "_id": {"$ne": current_user["_id"]},
        "role": {"$ne": "admin"}
    }):
        # Administrator accounts do not have learner skill fields and cannot match.
        if not candidate.get("teach_skill") or not candidate.get("learn_skill"):
            continue
        if not is_user_ready_to_exchange(candidate):
            continue

        if candidate["_id"] in handled_match_ids:
            continue

        user_can_learn_from_candidate = (
            normalise_skill(current_user.get("learn_skill", ""))
            == normalise_skill(candidate.get("teach_skill", ""))
        )

        candidate_can_learn_from_user = (
            normalise_skill(current_user.get("teach_skill", ""))
            == normalise_skill(candidate.get("learn_skill", ""))
        )

        if user_can_learn_from_candidate and candidate_can_learn_from_user:
            score, availability_message, level_message = calculate_compatibility(
                current_user,
                candidate
            )

            match = dict(candidate)
            match["compatibility_score"] = score
            match["availability_message"] = availability_message
            match["level_message"] = level_message
            matches.append(match)

    return sorted(matches, key=lambda match: match["compatibility_score"], reverse=True)


@app.route("/terms")
def terms():
    """Show user terms only as the step immediately before registration."""
    if session.get("user_id"):
        destination = "admin_dashboard" if session.get("user_role") == "admin" else "dashboard"
        return redirect(url_for(destination))
    if session.get("user_terms_accepted"):
        return redirect(url_for("register"))
    return render_template("terms.html")


@app.route("/terms/accept", methods=["POST"])
def accept_terms():
    """Record acceptance needed to open the user registration form."""
    if request.form.get("terms_agreement") != "accepted":
        return render_template(
            "terms.html",
            error="Please confirm that you agree to the Terms & Conditions to continue."
        ), 400
    session["user_terms_accepted"] = True
    session["user_terms_accepted_at"] = datetime.now(timezone.utc).isoformat()
    return redirect(url_for("register"))


@app.route("/admin/terms")
@admin_required
def admin_terms():
    """Show the one-time admin responsibility agreement after first login."""
    return render_template("admin_terms.html")


@app.route("/admin/terms/accept", methods=["POST"])
@admin_required
def accept_admin_terms():
    """Persist an administrator's agreement so it is not shown again."""
    if request.form.get("terms_agreement") != "accepted":
        return render_template(
            "admin_terms.html",
            error="Please confirm that you agree to the administrator terms to continue."
        ), 400
    users_collection.update_one(
        {"_id": ObjectId(session["user_id"]), "role": "admin"},
        {"$set": {"admin_terms_accepted_at": datetime.now(timezone.utc)}}
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/")
def splash():
    return redirect(url_for("home"))


@app.route("/home")
def home():
    # Signed-in people should not land back on the public welcome screen.
    account_id = session.get("user_id")
    if account_id and ObjectId.is_valid(account_id):
        user = users_collection.find_one({"_id": ObjectId(account_id)})
        if user:
            if user.get("role") == "admin":
                return redirect(url_for("admin_dashboard"))
            if user.get("onboarding_status") == "pending":
                return redirect(url_for("skill_swap_onboarding"))
            return redirect(url_for("dashboard"))

    match_cycles = [
        {
            "skills": "Python ↔ UI/UX",
            "reason": "You want to learn UI/UX and they want to learn Python. Your availability also overlaps."
        },
        {
            "skills": "Web Development ↔ Graphic Design",
            "reason": "You want to learn Graphic Design and they want to learn Web Development. Your schedules align."
        },
        {
            "skills": "Public Speaking ↔ Video Editing",
            "reason": "You want to learn Video Editing and they want to learn Public Speaking. You have a shared time slot."
        },
        {
            "skills": "JavaScript ↔ Photography",
            "reason": "You want to learn Photography and they want to learn JavaScript. Your learning goals complement each other."
        },
        {
            "skills": "Content Writing ↔ Data Analysis",
            "reason": "You want to learn Data Analysis and they want to learn Content Writing. Your availability overlaps."
        },
        {
            "skills": "Digital Illustration ↔ HTML & CSS",
            "reason": "You want to learn HTML & CSS and they want to learn Digital Illustration. You can learn together."
        },
        {
            "skills": "Excel ↔ Social Media Marketing",
            "reason": "You want to learn Social Media Marketing and they want to learn Excel. Your weekly schedules match."
        },
        {
            "skills": "Figma ↔ Python",
            "reason": "You want to learn Python and they want to learn Figma. Your skill levels are a good fit."
        },
        {
            "skills": "Spoken English ↔ Web Development",
            "reason": "You want to learn Web Development and they want to learn Spoken English. You are available at similar times."
        },
        {
            "skills": "Presentation Design ↔ Coding Basics",
            "reason": "You want to learn Coding Basics and they want to learn Presentation Design. This is a balanced exchange."
        }
    ]

    for match in match_cycles:
        match["score"] = random.randint(78, 98)

    return render_template("index.html", match_cycles=match_cycles)


@app.route("/register", methods=["GET", "POST"])
def register():
    # User terms belong only to account creation, never to later sign-ins.
    if not session.get("user_terms_accepted"):
        return redirect(url_for("terms"))

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        security_questions, security_question_error = create_security_questions(request.form)
        teach_skill = request.form["teach_skill"]
        learn_skill = request.form["learn_skill"]
        skill_level = request.form["skill_level"]
        availability = request.form["availability"]
        learning_duration = request.form["learning_duration"]
        certificate_file = request.files.get("certificate")
        profile_photo = request.files.get("profile_photo")

        # Check if email already exists
        existing_user = users_collection.find_one({"email": email})

        if existing_user:
            return render_template(
                "register.html",
                error="An account with this email already exists. Please log in instead."
            )

        if not has_valid_password(password):
            return render_template("register.html", error=PASSWORD_REQUIREMENTS_MESSAGE)

        if security_question_error:
            return render_template("register.html", error=security_question_error)

        needs_certificate = skill_level in ["Intermediate", "Advanced"]

        if needs_certificate and (
            not certificate_file or not certificate_file.filename
        ):
            return render_template(
                "register.html",
                error="Please upload a certificate for Intermediate or Advanced level."
            )

        if certificate_file and certificate_file.filename and not certificate_file_is_allowed(
            certificate_file.filename
        ):
            return render_template(
                "register.html",
                error="Certificate must be a PDF, PNG, JPG, or JPEG file."
            )

        if certificate_file and certificate_file.filename and not certificate_file_size_is_allowed(
            certificate_file
        ):
            return render_template(
                "register.html",
                error="Certificate files must be 10 MB or smaller."
            )

        if certificate_file and certificate_file.filename and not certificate_file_content_is_valid(
            certificate_file
        ):
            return render_template(
                "register.html",
                error="The certificate file does not match its selected PDF, PNG, JPG, or JPEG format."
            )

        if profile_photo and profile_photo.filename and not profile_photo_file_is_allowed(
            profile_photo.filename
        ):
            return render_template(
                "register.html",
                error="Profile photo must be a PNG, JPG, or JPEG file."
            )

        if profile_photo and profile_photo.filename and not profile_photo_file_size_is_allowed(
            profile_photo
        ):
            return render_template("register.html", error="Profile photos must be 5 MB or smaller.")

        # Hash password
        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        # Create user
        user = {
            "name": name,
            "email": email,
            "password": hashed_password,
            "security_questions": security_questions,
            "teach_skill": teach_skill,
            "learn_skill": learn_skill,
            "skill_level": skill_level,
            "availability": availability,
            "learning_duration": learning_duration,
            "role": "user",
            "created_at": datetime.now(timezone.utc),
            "terms_accepted_at": datetime.now(timezone.utc),
            "onboarding_status": "pending",
            "onboarding_card_choices": {}
        }

        if certificate_file and certificate_file.filename:
            certificate_proof = save_certificate_file(certificate_file)
            certificate_proof["skill"] = teach_skill
            certificate_proof["skill_level"] = skill_level
            user["certificate_proof"] = certificate_proof
            user["certificate_review"] = analyse_certificate(certificate_proof, user)

        if profile_photo and profile_photo.filename:
            user["profile_photo"] = save_profile_photo(profile_photo)

        # Store user in MongoDB
        insert_result = users_collection.insert_one(user)
        user["_id"] = insert_result.inserted_id

        review = user.get("certificate_review", {})
        if review.get("status") == "auto_verified":
            verification = make_skill_verification(user)
            users_collection.update_one(
                {"_id": user["_id"]}, {"$set": {"verification": verification}}
            )
            user["verification"] = verification
            award_user_badges(user)
            add_notification(
                user["_id"],
                "Your certificate matched your profile and your skill is now verified.",
                url_for("certificate")
            )
            add_activity(user["_id"], "Skill verified", "Your certificate details matched your profile.")
        elif review.get("status") in {"rejected", "pending"}:
            add_notification(
                user["_id"],
                "Your certificate needs attention. You cannot discover matches or take sessions until it is verified.",
                url_for("verify_skill"),
            )
        session.pop("user_terms_accepted", None)
        session.pop("user_terms_accepted_at", None)
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if login_is_rate_limited("user-login"):
            return render_template(
                "login.html",
                error="Too many sign-in attempts. Please wait 15 minutes before trying again."
            )

        email = request.form["email"]
        password = request.form["password"]

        # Find user in MongoDB
        user = users_collection.find_one({"email": email})

        # Check password
        if user and bcrypt.check_password_hash(
            user["password"], password
        ):

            clear_failed_logins("user-login")

            if suspension_is_active(user):
                suspended_until = user.get("suspended_until")
                suspension_date = suspended_until.strftime("%d %b %Y") if suspended_until else "seven days"
                return render_template(
                    "login.html",
                    error=f"This account is suspended until {suspension_date}."
                )

            # Create login session
            session.clear()
            session["user_id"] = str(user["_id"])
            session["user_name"] = user["name"]
            session["user_role"] = user.get("role", "user")

            if not has_complete_security_questions(user):
                return redirect(url_for("security_questions_setup"))

            if session["user_role"] != "admin" and user.get("onboarding_status") == "pending":
                return redirect(url_for("skill_swap_onboarding"))

            return redirect(
                url_for("admin_dashboard")
                if session["user_role"] == "admin"
                else url_for("dashboard")
            )

        # Wrong email or password
        record_failed_login("user-login")
        return render_template(
            "login.html",
            error="Invalid email or password. Please try again."
        )

    login_error = (
        "This account is currently suspended for seven days."
        if request.args.get("suspended") else None
    )
    return render_template("login.html", error=login_error, notice=request.args.get("notice"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Start password recovery after identifying the account holder."""
    role = request.args.get("role", request.form.get("role", "user"))
    role = "admin" if role == "admin" else "user"
    submitted = False

    if request.method == "POST":
        submitted = True
        if login_is_rate_limited("password-recovery"):
            return render_template("forgot_password.html", role=role, submitted=True)
        email = request.form.get("email", "").strip().lower()
        account = users_collection.find_one({"email": email, "role": role})
        if account and len(account.get("security_questions", [])) == 2:
            clear_failed_logins("password-recovery")
            session["password_recovery_account_id"] = str(account["_id"])
            session["password_recovery_role"] = role
            session["password_recovery_expires_at"] = (
                datetime.now(timezone.utc) + timedelta(minutes=10)
            ).timestamp()
            return redirect(url_for("verify_security_answers"))
        record_failed_login("password-recovery")

    return render_template(
        "forgot_password.html",
        role=role,
        submitted=submitted
    )


@app.route("/reset-password/security-questions", methods=["GET", "POST"])
def verify_security_answers():
    """Verify two saved recovery answers before issuing a one-time reset link."""
    account_id = session.get("password_recovery_account_id")
    expires_at = session.get("password_recovery_expires_at", 0)
    role = session.get("password_recovery_role", "user")

    if (
        not account_id
        or not ObjectId.is_valid(account_id)
        or datetime.now(timezone.utc).timestamp() > expires_at
    ):
        session.pop("password_recovery_account_id", None)
        session.pop("password_recovery_role", None)
        session.pop("password_recovery_expires_at", None)
        return redirect(url_for("forgot_password", role=role))

    account = users_collection.find_one({"_id": ObjectId(account_id), "role": role})
    questions = account.get("security_questions", []) if account else []
    if len(questions) != 2:
        return redirect(url_for("forgot_password", role=role))

    error = None
    if request.method == "POST":
        if login_is_rate_limited("security-answers"):
            error = "Too many recovery attempts. Please wait 15 minutes before trying again."
            return render_template(
                "verify_security_answers.html", role=role, questions=questions, error=error
            )
        answers = [
            normalize_security_answer(request.form.get("security_answer_one", "")),
            normalize_security_answer(request.form.get("security_answer_two", ""))
        ]
        answers_match = all(
            answer and bcrypt.check_password_hash(question["answer_hash"], answer)
            for answer, question in zip(answers, questions)
        )
        if not answers_match:
            record_failed_login("security-answers")
            error = "Those answers do not match our records. Please try again."
        else:
            clear_failed_logins("security-answers")
            token = uuid4().hex
            users_collection.update_one(
                {"_id": account["_id"]},
                {"$set": {
                    "password_reset_token_hash": hashlib.sha256(token.encode()).hexdigest(),
                    "password_reset_expires_at": datetime.now(timezone.utc) + timedelta(minutes=30)
                }}
            )
            session.pop("password_recovery_account_id", None)
            session.pop("password_recovery_role", None)
            session.pop("password_recovery_expires_at", None)
            return redirect(url_for("reset_password", token=token))

    return render_template(
        "verify_security_answers.html",
        role=role,
        questions=questions,
        error=error
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Set a new password using a reset link that expires after thirty minutes."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    account = users_collection.find_one({
        "password_reset_token_hash": token_hash,
        "password_reset_expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    error = None
    if not account:
        return render_template("reset_password.html", error="This reset link is invalid or has expired.")

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not has_valid_password(password):
            error = PASSWORD_REQUIREMENTS_MESSAGE
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            users_collection.update_one(
                {"_id": account["_id"]},
                {
                    "$set": {"password": bcrypt.generate_password_hash(password).decode("utf-8")},
                    "$unset": {"password_reset_token_hash": "", "password_reset_expires_at": ""}
                }
            )
            login_endpoint = "admin_login" if account.get("role") == "admin" else "login"
            return redirect(url_for(login_endpoint, notice="Password updated. You can now sign in."))

    return render_template("reset_password.html", error=error)


@app.route("/security-questions", methods=["GET", "POST"])
def security_questions_setup():
    """Let signed-in accounts configure the recovery questions used for resets."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("access_choice"))

    account = users_collection.find_one({"_id": ObjectId(account_id)})
    if not account:
        session.clear()
        return redirect(url_for("access_choice"))

    error = None
    if request.method == "POST":
        questions, error = create_security_questions(request.form)
        if not error:
            users_collection.update_one(
                {"_id": account["_id"]},
                {"$set": {"security_questions": questions}}
            )
            if account.get("role") == "admin" and not account.get("admin_terms_accepted_at"):
                destination = "admin_terms"
            else:
                destination = "admin_dashboard" if account.get("role") == "admin" else "dashboard"
            return redirect(url_for(destination))

    return render_template(
        "security_questions_setup.html",
        error=error,
        account_role=account.get("role", "user")
    )


@app.route("/access")
def access_choice():
    """Let visitors choose the correct access area before signing in."""
    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("access_choice.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Sign in an administrator without exposing admin access to normal users."""
    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        if login_is_rate_limited("admin-login"):
            return render_template(
                "admin_login.html",
                error="Too many sign-in attempts. Please wait 15 minutes before trying again."
            )
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = users_collection.find_one({"email": email})

        if (
            user
            and user.get("role") == "admin"
            and bcrypt.check_password_hash(user["password"], password)
        ):
            clear_failed_logins("admin-login")
            session.clear()
            session["user_id"] = str(user["_id"])
            session["user_name"] = user["name"]
            session["user_role"] = "admin"
            if not has_complete_security_questions(user):
                return redirect(url_for("security_questions_setup"))
            if not user.get("admin_terms_accepted_at"):
                return redirect(url_for("admin_terms"))
            return redirect(url_for("admin_dashboard"))

        record_failed_login("admin-login")
        return render_template(
            "admin_login.html",
            error="Admin email or password is incorrect. Use an administrator account, not a learner account."
        )

    return render_template("admin_login.html", notice=request.args.get("notice"))


@app.route("/admin/setup", methods=["GET", "POST"])
def admin_setup():
    """Legacy setup endpoint kept closed after admin provisioning."""
    return redirect(url_for(
        "admin_login",
        notice="Admin accounts are managed by the platform owner. Please sign in."
    ))



@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Show high-level, read-only platform information for the administrator."""
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    stats = {
        "total_users": users_collection.count_documents({"role": {"$ne": "admin"}}),
        "new_users": users_collection.count_documents({
            "role": {"$ne": "admin"},
            "created_at": {"$gte": seven_days_ago}
        }),
        "active_exchanges": matches_collection.count_documents({
            "action": "interested", "status": "accepted"
        }),
        "completed_exchanges": matches_collection.count_documents({
            "action": "interested", "status": "completed"
        }),
        "pending_requests": matches_collection.count_documents({
            "action": "interested", "status": "pending"
        }),
        "confirmed_sessions": sessions_collection.count_documents({"status": "confirmed"}),
        "verification_queue": users_collection.count_documents({
            "certificate_proof": {"$exists": True},
            "$or": [
                {"certificate_review": {"$exists": False}},
                {"certificate_review.status": "pending"}
            ]
        }),
        "open_reports": reports_collection.count_documents({"status": "open"})
    }
    recent_users = list(
        users_collection.find({"role": {"$ne": "admin"}})
        .sort("created_at", -1)
        .limit(5)
    )
    recent_platform_activity = []

    for activity in activities_collection.find().sort("created_at", -1).limit(10):
        user = users_collection.find_one({"_id": activity.get("user_id")})
        recent_platform_activity.append({
            "title": activity.get("title", "Platform activity"),
            "detail": activity.get("detail", ""),
            "actor": user.get("name", "A user") if user else "A user",
            "created_at": activity.get("created_at"),
            "type": "activity"
        })

    for report in reports_collection.find().sort("created_at", -1).limit(5):
        reporter = users_collection.find_one({"_id": report.get("reported_by")})
        recent_platform_activity.append({
            "title": "Safety report submitted",
            "detail": report.get("report_type", "Safety concern"),
            "actor": reporter.get("name", "A user") if reporter else "A user",
            "created_at": report.get("created_at"),
            "type": "report"
        })

    for user in users_collection.find({
        "role": {"$ne": "admin"},
        "created_at": {"$exists": True}
    }).sort("created_at", -1).limit(5):
        recent_platform_activity.append({
            "title": "New user registered",
            "detail": f"Ready to teach {user.get('teach_skill', 'a skill')}",
            "actor": user.get("name", "New user"),
            "created_at": user.get("created_at"),
            "type": "user"
        })

    recent_platform_activity.sort(
        key=lambda item: item.get("created_at") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True
    )
    recent_platform_activity = recent_platform_activity[:8]

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        recent_users=recent_users,
        recent_platform_activity=recent_platform_activity
    )


def get_admin_target_user(user_id):
    """Return a real user document for an admin action, or None for a bad ID."""
    if not ObjectId.is_valid(user_id):
        return None
    return users_collection.find_one({"_id": ObjectId(user_id)})


@app.route("/admin/users")
@admin_required
def admin_users():
    """List all accounts and optionally filter by a name or email search."""
    search = request.args.get("q", "").strip()
    query = {}
    if search:
        safe_search = re.escape(search)
        query["$or"] = [
            {"name": {"$regex": safe_search, "$options": "i"}},
            {"email": {"$regex": safe_search, "$options": "i"}}
        ]

    platform_users = list(
        users_collection.find(query).sort("created_at", -1).limit(100)
    )
    for platform_user in platform_users:
        platform_user["is_suspended"] = suspension_is_active(platform_user)
        platform_user["reputation"] = get_user_reputation(platform_user["_id"])
        platform_user["badge_count"] = badges_collection.count_documents({
            "user_id": platform_user["_id"]
        })

    return render_template(
        "admin_users.html",
        users=platform_users,
        search=search
    )


@app.route("/admin/users/<user_id>")
@admin_required
def admin_user_profile(user_id):
    """Show the full account information available to the administrator."""
    user = get_admin_target_user(user_id)
    if not user:
        return redirect(url_for("admin_users"))

    user["is_suspended"] = suspension_is_active(user)
    user["reputation"] = get_user_reputation(user["_id"])
    user_badges = list(
        badges_collection.find({"user_id": user["_id"]}).sort("earned_at", -1)
    )
    connections = list(matches_collection.find({
        "$or": [{"from_user_id": user["_id"]}, {"to_user_id": user["_id"]}]
    }).sort("created_at", -1).limit(8))
    for connection in connections:
        partner_id = (
            connection.get("to_user_id")
            if connection.get("from_user_id") == user["_id"]
            else connection.get("from_user_id")
        )
        partner = users_collection.find_one({"_id": partner_id})
        connection["partner_name"] = partner.get("name", "Removed user") if partner else "Removed user"

    return render_template(
        "admin_user_profile.html",
        user=user,
        badges=user_badges,
        connections=connections,
        admin_user_id=session.get("user_id")
    )


@app.route("/admin/users/<user_id>/status", methods=["POST"])
@admin_required
def admin_user_status(user_id):
    """Suspend or activate a normal learner account."""
    user = get_admin_target_user(user_id)
    if not user or user.get("role") == "admin":
        return redirect(url_for("admin_users"))

    is_suspended = not suspension_is_active(user)
    update = {"$set": {"is_suspended": is_suspended}}
    if is_suspended:
        update["$set"]["suspended_until"] = datetime.now(timezone.utc) + timedelta(days=7)
    else:
        update["$unset"] = {"suspended_until": ""}
    users_collection.update_one({"_id": user["_id"]}, update)
    return redirect(url_for("admin_user_profile", user_id=user_id))


def delete_user_records(user):
    """Permanently remove one learner's direct records and private uploads."""
    connection_ids = [
        connection["_id"]
        for connection in matches_collection.find({
            "$or": [{"from_user_id": user["_id"]}, {"to_user_id": user["_id"]}]
        }, {"_id": 1})
    ]
    if connection_ids:
        sessions_collection.delete_many({"connection_id": {"$in": connection_ids}})
        messages_collection.delete_many({"connection_id": {"$in": connection_ids}})
        reports_collection.delete_many({"connection_id": {"$in": connection_ids}})
        matches_collection.delete_many({"_id": {"$in": connection_ids}})

    reviews_collection.delete_many({
        "$or": [{"reviewed_user_id": user["_id"]}, {"reviewer_id": user["_id"]}]
    })
    badges_collection.delete_many({"user_id": user["_id"]})
    notifications_collection.delete_many({"user_id": user["_id"]})
    activities_collection.delete_many({"user_id": user["_id"]})
    delete_uploaded_file(CERTIFICATE_UPLOAD_FOLDER, user.get("certificate_proof", {}).get("filename"))
    delete_uploaded_file(PROFILE_PHOTO_UPLOAD_FOLDER, user.get("profile_photo"))
    users_collection.delete_one({"_id": user["_id"]})


@app.route("/admin/users/<user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Permanently remove a learner and their directly-owned platform records."""
    user = get_admin_target_user(user_id)
    if not user or user.get("role") == "admin":
        return redirect(url_for("admin_users"))

    delete_user_records(user)
    return redirect(url_for("admin_users"))


@app.route("/admin/verifications")
@admin_required
def admin_verifications():
    """Show certificate proof for administrator review."""
    selected_status = request.args.get("status", "pending")
    if selected_status not in {"pending", "approved", "auto_verified", "rejected", "all"}:
        selected_status = "pending"

    query = {"certificate_proof": {"$exists": True}}
    if selected_status == "pending":
        query["$or"] = [
            {"certificate_review": {"$exists": False}},
            {"certificate_review.status": "pending"}
        ]
    elif selected_status != "all":
        query["certificate_review.status"] = selected_status

    verification_users = list(users_collection.find(query).sort("created_at", -1))
    for user in verification_users:
        user["review"] = user.get("certificate_review", {"status": "pending"})

    return render_template(
        "admin_verifications.html",
        users=verification_users,
        selected_status=selected_status
    )


@app.route("/admin/verifications/<user_id>/proof")
@admin_required
def admin_certificate_proof(user_id):
    """Let an administrator inspect the certificate uploaded by a user."""
    user = get_admin_target_user(user_id)
    proof = user.get("certificate_proof", {}) if user else {}
    if not proof.get("filename"):
        return redirect(url_for("admin_verifications"))
    return send_from_directory(CERTIFICATE_UPLOAD_FOLDER, proof["filename"])


@app.route("/admin/verifications/<user_id>/approve", methods=["POST"])
@admin_required
def admin_approve_certificate(user_id):
    """Approve a certificate; issuing final verification remains a separate step."""
    user = get_admin_target_user(user_id)
    if not user or not user.get("certificate_proof"):
        return redirect(url_for("admin_verifications"))

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"certificate_review": {
            "status": "approved", "reviewed_at": datetime.now(timezone.utc),
            "reviewed_by": ObjectId(session["user_id"]), "reason": ""
        }}}
    )
    add_notification(user["_id"], "Your uploaded certificate was approved by SkillSwap.", url_for("verify_skill"))
    add_activity(user["_id"], "Certificate approved", "Your uploaded skill proof passed review.")
    return redirect(url_for("admin_verifications", status="pending"))


@app.route("/admin/verifications/<user_id>/reject", methods=["POST"])
@admin_required
def admin_reject_certificate(user_id):
    """Reject proof with a reason and revoke a now-invalid skill verification."""
    user = get_admin_target_user(user_id)
    reason = request.form.get("reason", "").strip()[:500]
    if not user or not user.get("certificate_proof") or not reason:
        return redirect(url_for("admin_verifications"))

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"certificate_review": {
            "status": "rejected", "reviewed_at": datetime.now(timezone.utc),
            "reviewed_by": ObjectId(session["user_id"]), "reason": reason
        }}, "$unset": {"verification": ""}}
    )
    badges_collection.delete_many({"user_id": user["_id"], "name": "Verified Mentor"})
    add_notification(user["_id"], f"Your certificate needs an update: {reason}", url_for("edit_profile"))
    add_activity(user["_id"], "Certificate review needs changes", reason)
    return redirect(url_for("admin_verifications", status="pending"))


@app.route("/admin/verifications/<user_id>/override", methods=["POST"])
@admin_required
def admin_override_certificate(user_id):
    """Let an administrator correct an overly strict automated rejection."""
    user = get_admin_target_user(user_id)
    review = user.get("certificate_review", {}) if user else {}
    if not user or not user.get("certificate_proof") or review.get("status") != "rejected":
        return redirect(url_for("admin_verifications"))

    verification = make_skill_verification(user)
    verification["verification_method"] = "admin_override"
    verification["verified_by_admin"] = ObjectId(session["user_id"])
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "certificate_review": {
                "status": "approved",
                "reviewed_at": datetime.now(timezone.utc),
                "reviewed_by": ObjectId(session["user_id"]),
                "reason": "Approved by an administrator after reviewing the uploaded certificate.",
                "automated": False,
            },
            "verification": verification,
        }},
    )
    user["verification"] = verification
    award_user_badges(user)
    add_notification(
        user["_id"],
        "Your certificate was approved by a SkillSwap administrator.",
        url_for("certificate"),
    )
    add_activity(user["_id"], "Skill verified", "An administrator approved your certificate.")
    return redirect(url_for("admin_verifications", status="rejected"))


@app.route("/admin/verifications/<user_id>/mark-verified", methods=["POST"])
@admin_required
def admin_mark_skill_verified(user_id):
    """Mark a skill verified after an administrator approves its proof."""
    user = get_admin_target_user(user_id)
    review = user.get("certificate_review", {}) if user else {}
    if (
        not user or not user.get("certificate_proof")
        or review.get("status") != "approved"
    ):
        return redirect(url_for("admin_verifications"))

    verification = {
        "skill": user["certificate_proof"].get("skill", user.get("teach_skill")),
        "skill_level": user["certificate_proof"].get("skill_level", user.get("skill_level")),
        "passed": True, "verified_at": datetime.now(timezone.utc),
        "verified_by_admin": ObjectId(session["user_id"]),
        "certificate_id": f"SS-{str(user['_id'])[-8:].upper()}-{datetime.now(timezone.utc).year}"
    }
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"verification": verification}})
    user["verification"] = verification
    award_user_badges(user)
    add_notification(user["_id"], "Your skill is now officially verified on SkillSwap.", url_for("certificate"))
    add_activity(user["_id"], "Skill verified", f"Your {verification['skill']} skill is officially verified.")
    return redirect(url_for("admin_verifications", status="approved"))


def get_reported_user(report):
    """Find the other exchange participant named in a safety report."""
    reported_user_id = report.get("reported_user_id")
    if reported_user_id:
        return users_collection.find_one({"_id": reported_user_id})
    connection = matches_collection.find_one({"_id": report.get("connection_id")})
    if not connection:
        return None
    other_user_id = connection.get("to_user_id") if connection.get("from_user_id") == report.get("reported_by") else connection.get("from_user_id")
    return users_collection.find_one({"_id": other_user_id})


@app.route("/admin/reports")
@admin_required
def admin_reports():
    """Show platform safety reports with the users and exchange involved."""
    selected_status = request.args.get("status", "open")
    if selected_status not in {"open", "under_review", "resolved", "all"}:
        selected_status = "open"
    query = {} if selected_status == "all" else {"status": selected_status}
    safety_reports = list(reports_collection.find(query).sort("created_at", -1))
    for report in safety_reports:
        reporter = users_collection.find_one({"_id": report.get("reported_by")})
        reported_user = get_reported_user(report)
        connection = matches_collection.find_one({"_id": report.get("connection_id")})
        report["reporter_name"] = reporter.get("name", "Removed user") if reporter else "Removed user"
        if reported_user:
            reported_user["is_suspended"] = suspension_is_active(reported_user)
        report["reported_user"] = reported_user
        report["reported_user_name"] = reported_user.get("name", "Unknown user") if reported_user else "Unknown user"
        report["connection_label"] = f"{connection.get('status', 'unknown').capitalize()} exchange" if connection else "Connection no longer available"
    return render_template("admin_reports.html", reports=safety_reports, selected_status=selected_status)


@app.route("/admin/reports/<report_id>/status", methods=["POST"])
@admin_required
def admin_report_status(report_id):
    """Move a safety report through Open, Under Review, and Resolved states."""
    if not ObjectId.is_valid(report_id):
        return redirect(url_for("admin_reports"))
    status = request.form.get("status")
    if status not in {"open", "under_review", "resolved"}:
        return redirect(url_for("admin_reports"))
    reports_collection.update_one({"_id": ObjectId(report_id)}, {"$set": {
        "status": status, "updated_at": datetime.now(timezone.utc),
        "updated_by": ObjectId(session["user_id"])
    }})
    return redirect(url_for("admin_reports", status=status))


@app.route("/admin/reports/<report_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend_reported_user(report_id):
    """Suspend the reported learner when an admin decides action is necessary."""
    if not ObjectId.is_valid(report_id):
        return redirect(url_for("admin_reports"))
    report = reports_collection.find_one({"_id": ObjectId(report_id)})
    reported_user = get_reported_user(report) if report else None
    if not reported_user or reported_user.get("role") == "admin":
        return redirect(url_for("admin_reports"))
    users_collection.update_one(
        {"_id": reported_user["_id"]},
        {"$set": {
            "is_suspended": True,
            "suspended_until": datetime.now(timezone.utc) + timedelta(days=7)
        }}
    )
    reports_collection.update_one({"_id": report["_id"]}, {"$set": {
        "status": "under_review", "action_taken": "Reported user suspended",
        "updated_at": datetime.now(timezone.utc)
    }})
    add_notification(reported_user["_id"], "Your SkillSwap account has been suspended for seven days while a safety report is reviewed.")
    return redirect(url_for("admin_reports", status="under_review"))


@app.route("/admin/reports/<report_id>/cancel-exchange", methods=["POST"])
@admin_required
def admin_cancel_reported_exchange(report_id):
    """Cancel an exchange connected to a safety report without deleting its history."""
    if not ObjectId.is_valid(report_id):
        return redirect(url_for("admin_reports"))
    report = reports_collection.find_one({"_id": ObjectId(report_id)})
    connection = matches_collection.find_one({"_id": report.get("connection_id")}) if report else None
    if not connection:
        return redirect(url_for("admin_reports"))
    matches_collection.update_one({"_id": connection["_id"]}, {"$set": {
        "status": "cancelled", "cancelled_at": datetime.now(timezone.utc),
        "cancelled_by_admin": ObjectId(session["user_id"])
    }})
    reports_collection.update_one({"_id": report["_id"]}, {"$set": {
        "status": "under_review", "action_taken": "Exchange cancelled by administrator",
        "updated_at": datetime.now(timezone.utc)
    }})
    for participant_id in [connection.get("from_user_id"), connection.get("to_user_id")]:
        if participant_id:
            add_notification(participant_id, "This SkillSwap exchange was cancelled by an administrator during a safety review.")
    return redirect(url_for("admin_reports", status="under_review"))


@app.route("/admin/matches")
@admin_required
def admin_matches():
    """Monitor connection requests, compatibility details, and active exchanges."""
    selected_status = request.args.get("status", "all")
    valid_statuses = {"pending", "accepted", "rejected", "completed", "cancelled", "all"}
    if selected_status not in valid_statuses:
        selected_status = "all"

    query = {"action": "interested"}
    if selected_status != "all":
        query["status"] = selected_status
    monitored_matches = list(matches_collection.find(query).sort("updated_at", -1).limit(150))

    for connection in monitored_matches:
        requester = users_collection.find_one({"_id": connection.get("from_user_id")})
        partner = users_collection.find_one({"_id": connection.get("to_user_id")})
        connection["requester"] = requester
        connection["partner"] = partner
        if requester and partner:
            score, availability_reason, level_reason = calculate_compatibility(requester, partner)
            connection["compatibility_score"] = score
            connection["matching_reason"] = (
                f"Complementary skills · {availability_reason} · {level_reason}"
            )
        else:
            connection["compatibility_score"] = None
            connection["matching_reason"] = "One account is no longer available."

    active_exchange_count = matches_collection.count_documents({
        "action": "interested", "status": "accepted"
    })
    return render_template(
        "admin_matches.html",
        matches=monitored_matches,
        selected_status=selected_status,
        active_exchange_count=active_exchange_count
    )


@app.route("/admin/matches/<connection_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_connection(connection_id):
    """Cancel a pending or active exchange where an admin has a safety concern."""
    if not ObjectId.is_valid(connection_id):
        return redirect(url_for("admin_matches"))
    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": {"$in": ["pending", "accepted"]}
    })
    if not connection:
        return redirect(url_for("admin_matches"))

    reason = request.form.get("reason", "").strip()[:500]
    matches_collection.update_one(
        {"_id": connection["_id"]},
        {"$set": {
            "status": "cancelled",
            "cancelled_at": datetime.now(timezone.utc),
            "cancelled_by_admin": ObjectId(session["user_id"]),
            "cancellation_reason": reason or "Cancelled by administrator for safety review."
        }}
    )
    for participant_id in [connection.get("from_user_id"), connection.get("to_user_id")]:
        if participant_id:
            add_notification(
                participant_id,
                "Your SkillSwap connection was cancelled by an administrator for a safety review."
            )
    return redirect(url_for("admin_matches", status="cancelled"))


@app.route("/dashboard")
def dashboard():

    # Send visitors to login if they are not logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get the logged-in user's profile details from MongoDB
    user = users_collection.find_one({
        "_id": ObjectId(session["user_id"])
    })
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if user.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if user.get("onboarding_status") == "pending":
        return redirect(url_for("skill_swap_onboarding"))

    active_exchange_count = matches_collection.count_documents({
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": user["_id"]},
            {"to_user_id": user["_id"]}
        ]
    })

    completed_exchange_count = matches_collection.count_documents({
        "action": "interested",
        "status": "completed",
        "$or": [
            {"from_user_id": user["_id"]},
            {"to_user_id": user["_id"]}
        ]
    })
    reputation = get_user_reputation(user["_id"])
    award_user_badges(user)
    badges = list(badges_collection.find({"user_id": user["_id"]}))
    recent_activity = list(
        activities_collection.find({"user_id": user["_id"]})
        .sort("created_at", -1)
        .limit(4)
    )

    return render_template(
        "dashboard.html",
        user=user,
        active_exchange_count=active_exchange_count,
        completed_exchange_count=completed_exchange_count,
        reputation=reputation,
        badges=badges,
        verification=user.get("verification"),
        verification_required=requires_skill_verification(user),
        certificate_uploaded=has_matching_certificate(user),
        verification_valid=is_skill_verified(user),
        onboarding_status=user.get("onboarding_status", "completed"),
        recent_activity=recent_activity
    )


@app.route("/skill-swap")
def skill_swap_onboarding():
    """Let newly registered learners choose interests from a safe demo card deck."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if user.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    choices = user.get("onboarding_card_choices")
    choices = choices if isinstance(choices, dict) else {}
    cards = [card for card in ONBOARDING_DEMO_CARDS if card["id"] not in choices]
    return render_template(
        "skill_swap_onboarding.html",
        cards=cards,
        completed_count=len(ONBOARDING_DEMO_CARDS) - len(cards),
        total_count=len(ONBOARDING_DEMO_CARDS),
    )


@app.route("/skill-swap/card-action", methods=["POST"])
def skill_swap_card_action():
    """Save a learner's demo-card preference without creating a real connection."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return jsonify({"error": "Please log in again."}), 401

    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return jsonify({"error": "This card deck is for learner accounts."}), 403

    data = request.get_json(silent=True) or {}
    card_id = data.get("card_id")
    action = data.get("action")
    allowed_card_ids = {card["id"] for card in ONBOARDING_DEMO_CARDS}
    if card_id not in allowed_card_ids or action not in {"pass", "interested"}:
        return jsonify({"error": "That card choice is not valid."}), 400

    choices = user.get("onboarding_card_choices")
    choices = dict(choices) if isinstance(choices, dict) else {}
    choices[card_id] = action
    completed = allowed_card_ids.issubset(choices)
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "onboarding_card_choices": choices,
            "onboarding_status": "completed" if completed else user.get("onboarding_status", "pending"),
        }}
    )
    return jsonify({
        "message": "Skill saved for later matching." if action == "interested" else "Card passed.",
        "completed": completed,
    })


@app.route("/skill-swap/skip", methods=["POST"])
def skip_skill_swap_onboarding():
    """Let a learner leave the optional demo deck and resume it later."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"onboarding_status": "deferred"}}
    )
    return redirect(url_for("dashboard"))


def export_value(value):
    """Convert database values to JSON without exposing authentication secrets."""
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [export_value(item) for item in value]
    if isinstance(value, dict):
        private_fields = {
            "password", "security_questions", "password_reset_token_hash",
            "password_reset_expires_at", "_id",
        }
        return {
            key: export_value(item)
            for key, item in value.items()
            if key not in private_fields
        }
    return value


@app.route("/account")
def account_settings():
    """Give learners a single place to export or permanently delete their data."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))
    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))
    return render_template(
        "account_settings.html",
        user=user,
        notification_preferences=notification_preferences_for(user),
    )


@app.route("/account/notifications", methods=["POST"])
def update_notification_preferences():
    """Save a learner's explicit email-notification preference."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))
    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))
    preferences = notification_preferences_for(user)
    preferences["email"] = request.form.get("email_notifications") == "on"
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"notification_preferences": preferences}},
    )
    return redirect(url_for("account_settings"))


def valid_push_subscription(subscription):
    keys = subscription.get("keys", {}) if isinstance(subscription, dict) else {}
    endpoint = subscription.get("endpoint", "") if isinstance(subscription, dict) else ""
    return (
        isinstance(endpoint, str)
        and endpoint.startswith("https://")
        and isinstance(keys.get("p256dh"), str)
        and isinstance(keys.get("auth"), str)
    )


@app.route("/api/push-subscription", methods=["POST"])
def save_push_subscription():
    """Save a browser's opted-in Web Push subscription for the signed-in learner."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return jsonify({"ok": False, "error": "Please sign in again."}), 401
    subscription = request.get_json(silent=True)
    if not valid_push_subscription(subscription):
        return jsonify({"ok": False, "error": "Invalid browser push subscription."}), 400
    user_id = ObjectId(account_id)
    users_collection.update_one(
        {"_id": user_id}, {"$pull": {"push_subscriptions": {"endpoint": subscription["endpoint"]}}}
    )
    preferences = notification_preferences_for(users_collection.find_one({"_id": user_id}))
    preferences["push"] = True
    users_collection.update_one(
        {"_id": user_id},
        {"$push": {"push_subscriptions": subscription}, "$set": {"notification_preferences": preferences}},
    )
    return jsonify({"ok": True})


@app.route("/api/push-subscription", methods=["DELETE"])
def delete_push_subscription():
    """Stop push delivery for the browser subscription the learner removes."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return jsonify({"ok": False, "error": "Please sign in again."}), 401
    subscription = request.get_json(silent=True) or {}
    endpoint = subscription.get("endpoint", "")
    if not isinstance(endpoint, str):
        return jsonify({"ok": False, "error": "Invalid browser push subscription."}), 400
    user_id = ObjectId(account_id)
    users_collection.update_one(
        {"_id": user_id}, {"$pull": {"push_subscriptions": {"endpoint": endpoint}}}
    )
    remaining = users_collection.count_documents({"_id": user_id, "push_subscriptions.0": {"$exists": True}})
    if not remaining:
        user = users_collection.find_one({"_id": user_id})
        preferences = notification_preferences_for(user)
        preferences["push"] = False
        users_collection.update_one({"_id": user_id}, {"$set": {"notification_preferences": preferences}})
    return jsonify({"ok": True})


@app.route("/account/export")
def account_export():
    """Download the signed-in learner's stored account data as JSON."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))
    user_id = ObjectId(account_id)
    user = users_collection.find_one({"_id": user_id})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))

    export = {
        "exported_at": datetime.now(timezone.utc),
        "profile": user,
        "connections": list(matches_collection.find({
            "$or": [{"from_user_id": user_id}, {"to_user_id": user_id}]
        })),
        "notifications": list(notifications_collection.find({"user_id": user_id})),
        "activity": list(activities_collection.find({"user_id": user_id})),
        "badges": list(badges_collection.find({"user_id": user_id})),
    }
    response = jsonify(export_value(export))
    response.headers["Content-Disposition"] = "attachment; filename=skillswap-account-data.json"
    return response


@app.route("/account/delete", methods=["POST"])
def delete_own_account():
    """Delete a learner's account only after password and typed confirmation."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))
    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))

    password = request.form.get("password", "")
    confirmation = request.form.get("confirmation", "").strip()
    if confirmation != "DELETE" or not bcrypt.check_password_hash(user["password"], password):
        return render_template(
            "account_settings.html",
            user=user,
            notification_preferences=notification_preferences_for(user),
            error="Enter your current password and type DELETE exactly to confirm account deletion."
        )

    delete_user_records(user)
    session.clear()
    return redirect(url_for("home", account_deleted="1"))


@app.route("/certificate/remove", methods=["POST"])
def remove_own_certificate():
    """Let a learner explicitly remove their certificate and its verification."""
    account_id = session.get("user_id")
    if not account_id or not ObjectId.is_valid(account_id):
        return redirect(url_for("login"))
    user = users_collection.find_one({"_id": ObjectId(account_id)})
    if not user or user.get("role") == "admin":
        return redirect(url_for("dashboard"))
    proof = user.get("certificate_proof", {})
    if not proof.get("filename"):
        return redirect(url_for("edit_profile"))
    if request.form.get("confirmation", "").strip() != "REMOVE":
        return render_template(
            "edit_profile.html",
            user=user,
            error="Type REMOVE exactly to delete your certificate."
        )

    delete_uploaded_file(CERTIFICATE_UPLOAD_FOLDER, proof["filename"])
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$unset": {
            "certificate_proof": "",
            "certificate_review": "",
            "verification": "",
            "verification_test": "",
        }},
    )
    badges_collection.delete_many({"user_id": user["_id"], "name": "Verified Mentor"})
    add_activity(
        user["_id"],
        "Certificate removed",
        "You removed your certificate and its related skill verification.",
    )
    return redirect(url_for("edit_profile"))


@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    # Send visitors to login if they are not logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = ObjectId(session["user_id"])
    user = users_collection.find_one({"_id": user_id})

    if request.method == "POST":
        previous_certificate_filename = user.get("certificate_proof", {}).get("filename")
        previous_profile_photo = user.get("profile_photo")
        updated_profile = {
            "name": request.form["name"],
            "teach_skill": request.form["teach_skill"],
            "learn_skill": request.form["learn_skill"],
            "skill_level": request.form["skill_level"],
            "availability": request.form["availability"],
            "learning_duration": request.form["learning_duration"],
            "bio": request.form.get("bio", "").strip()[:300]
        }
        certificate_file = request.files.get("certificate")
        profile_photo = request.files.get("profile_photo")
        profile_with_updates = {**user, **updated_profile}
        needs_certificate = requires_skill_verification(profile_with_updates)
        already_has_certificate = has_matching_certificate(profile_with_updates)

        if needs_certificate and not already_has_certificate and (
            not certificate_file or not certificate_file.filename
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html",
                user=user,
                error="Please upload a certificate for Intermediate or Advanced level."
            )

        if certificate_file and certificate_file.filename and not certificate_file_is_allowed(
            certificate_file.filename
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html",
                user=user,
                error="Certificate must be a PDF, PNG, JPG, or JPEG file."
            )

        if certificate_file and certificate_file.filename and not certificate_file_size_is_allowed(
            certificate_file
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html",
                user=user,
                error="Certificate files must be 10 MB or smaller."
            )

        if certificate_file and certificate_file.filename and not certificate_file_content_is_valid(
            certificate_file
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html",
                user=user,
                error="The certificate file does not match its selected PDF, PNG, JPG, or JPEG format."
            )

        if profile_photo and profile_photo.filename and not profile_photo_file_is_allowed(
            profile_photo.filename
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html",
                user=user,
                error="Profile photo must be a PNG, JPG, or JPEG file."
            )

        if profile_photo and profile_photo.filename and not profile_photo_file_size_is_allowed(
            profile_photo
        ):
            user.update(updated_profile)
            return render_template(
                "edit_profile.html", user=user, error="Profile photos must be 5 MB or smaller."
            )

        if certificate_file and certificate_file.filename:
            certificate_proof = save_certificate_file(certificate_file)
            certificate_proof["skill"] = updated_profile["teach_skill"]
            certificate_proof["skill_level"] = updated_profile["skill_level"]
            updated_profile["certificate_proof"] = certificate_proof
            updated_profile["certificate_review"] = analyse_certificate(
                certificate_proof, profile_with_updates
            )

        if profile_photo and profile_photo.filename:
            updated_profile["profile_photo"] = save_profile_photo(profile_photo)

        # Save the updated details in MongoDB
        update_operation = {"$set": updated_profile}
        if certificate_file and certificate_file.filename:
            review = updated_profile["certificate_review"]
            if review.get("status") == "auto_verified":
                verification = make_skill_verification({**user, **updated_profile})
                updated_profile["verification"] = verification
                update_operation["$set"]["verification"] = verification
            else:
                update_operation["$unset"] = {"verification": "", "verification_test": ""}
        users_collection.update_one({"_id": user_id}, update_operation)

        if certificate_file and certificate_file.filename:
            new_certificate_filename = updated_profile["certificate_proof"]["filename"]
            if previous_certificate_filename != new_certificate_filename:
                delete_uploaded_file(CERTIFICATE_UPLOAD_FOLDER, previous_certificate_filename)
        if profile_photo and profile_photo.filename:
            if previous_profile_photo != updated_profile["profile_photo"]:
                delete_uploaded_file(PROFILE_PHOTO_UPLOAD_FOLDER, previous_profile_photo)

        if certificate_file and certificate_file.filename:
            review = updated_profile["certificate_review"]
            if review.get("status") == "auto_verified":
                user.update(updated_profile)
                award_user_badges(user)
                add_notification(
                    user_id,
                    "Your certificate matched your profile and your skill is now verified.",
                    url_for("certificate")
                )
                add_activity(user_id, "Skill verified", "Your certificate details matched your profile.")
            elif review.get("status") == "rejected":
                add_notification(
                    user_id,
                    "Your certificate details did not match your profile. Please upload a corrected certificate.",
                    url_for("edit_profile")
                )

        # Keep the session name up to date too
        session["user_name"] = updated_profile["name"]
        add_activity(user_id, "Profile updated", "Your profile details are ready for better matching.")

        return redirect(url_for("dashboard"))

    return render_template("edit_profile.html", user=user)


@app.route("/profile-photo/<filename>")
def profile_photo(filename):
    return send_from_directory(PROFILE_PHOTO_UPLOAD_FOLDER, filename)


@app.route("/verify-skill")
def verify_skill():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({
        "_id": ObjectId(session["user_id"])
    })
    verification_required = requires_skill_verification(user)
    certificate_uploaded = has_matching_certificate(user)
    return render_template(
        "verify_skill.html",
        user=user,
        verification_required=verification_required,
        certificate_uploaded=certificate_uploaded
    )


@app.route("/certificate-proof/<filename>")
def certificate_proof(filename):
    """Let a signed-in user view only their own uploaded proof."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    proof = user.get("certificate_proof", {})

    if proof.get("filename") != filename:
        abort(403)

    return send_from_directory(CERTIFICATE_UPLOAD_FOLDER, filename)


@app.route("/certificate")
def certificate():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({
        "_id": ObjectId(session["user_id"])
    })
    verification = user.get("verification")

    if not verification or not is_skill_verified(user):
        return redirect(url_for("verify_skill"))

    return render_template(
        "certificate.html",
        user=user,
        verification=verification
    )


def get_completed_exchange_for_user(connection_id, current_user_id):
    """Return a completed exchange only when the user belongs to it."""
    if not ObjectId.is_valid(connection_id):
        return None

    return matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "completed",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })


@app.route("/exchange-certificates/<connection_id>")
def exchange_certificates(connection_id):
    """Show a user's teaching and learning completion certificates."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})
    connection = get_completed_exchange_for_user(connection_id, current_user_id)
    if not connection:
        return redirect(url_for("connections"))

    current_user = users_collection.find_one({"_id": current_user_id})
    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    partner = users_collection.find_one({"_id": partner_id})

    return render_template(
        "exchange_certificates.html",
        connection=connection,
        user=current_user,
        partner=partner
    )


@app.route("/exchange-certificate/<connection_id>/<certificate_type>")
def exchange_certificate(connection_id, certificate_type):
    """Render one reciprocal certificate from a completed exchange."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    if certificate_type not in ["teaching", "learning"]:
        return redirect(url_for("connections"))

    current_user_id = ObjectId(session["user_id"])
    connection = get_completed_exchange_for_user(connection_id, current_user_id)
    if not connection:
        return redirect(url_for("connections"))

    current_user = users_collection.find_one({"_id": current_user_id})
    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    partner = users_collection.find_one({"_id": partner_id})

    if certificate_type == "teaching":
        heading = "Teaching Exchange Certificate"
        skill = current_user["teach_skill"]
        achievement = f"for teaching {skill} to {partner['name']}"
        certificate_code = "T"
    else:
        heading = "Learning Exchange Certificate"
        skill = partner["teach_skill"]
        achievement = f"for completing a learning exchange in {skill} with {partner['name']}"
        certificate_code = "L"

    completion_date = connection.get("completed_at", datetime.now(timezone.utc))
    certificate_id = (
        f"EX-{str(connection['_id'])[-8:].upper()}-"
        f"{certificate_code}-{str(current_user_id)[-4:].upper()}"
    )

    return render_template(
        "exchange_certificate.html",
        user=current_user,
        partner=partner,
        heading=heading,
        skill=skill,
        achievement=achievement,
        completion_date=completion_date,
        certificate_id=certificate_id,
        connection=connection
    )


@app.route("/matches")
def matches():

    # Only logged-in users can discover matches
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = users_collection.find_one({
        "_id": ObjectId(session["user_id"])
    })

    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))

    complementary_matches = find_complementary_matches(current_user)
    selected_level = request.args.get("level", "")
    selected_availability = request.args.get("availability", "")

    if selected_level in ["Beginner", "Intermediate", "Advanced"]:
        complementary_matches = [
            match for match in complementary_matches
            if match.get("skill_level") == selected_level
        ]

    if selected_availability == "aligned":
        complementary_matches = [
            match for match in complementary_matches
            if match.get("availability_message") == "Availability aligns"
        ]
    has_passed_match = matches_collection.find_one({
        "from_user_id": current_user["_id"],
        "action": "pass",
        "status": "passed"
    }) is not None

    return render_template(
        "matches.html",
        matches=complementary_matches,
        has_passed_match=has_passed_match,
        current_user=current_user,
        selected_level=selected_level,
        selected_availability=selected_availability
    )


@app.route("/matches/<match_id>/action", methods=["POST"])
def match_action(match_id):

    if "user_id" not in session:
        return jsonify({"error": "Please log in again."}), 401

    request_data = request.get_json(silent=True) or {}
    action = request_data.get("action")

    if action not in ["pass", "interested"]:
        return jsonify({"error": "Invalid match action."}), 400

    current_user = users_collection.find_one({
        "_id": ObjectId(session["user_id"])
    })
    if not is_user_ready_to_exchange(current_user):
        return jsonify({
            "error": "Upload your certificate and pass verification before matching."
        }), 403

    candidate_id = ObjectId(match_id)
    complementary_matches = find_complementary_matches(current_user)
    candidate = next(
        (match for match in complementary_matches if match["_id"] == candidate_id),
        None
    )

    if not candidate:
        return jsonify({"error": "This match is no longer available."}), 404

    match_record = {
        "from_user_id": current_user["_id"],
        "to_user_id": candidate_id,
        "action": action,
        "status": "pending" if action == "interested" else "passed",
        "updated_at": datetime.now(timezone.utc)
    }

    matches_collection.update_one(
        {
            "from_user_id": current_user["_id"],
            "to_user_id": candidate_id
        },
        {"$set": match_record},
        upsert=True
    )

    if action == "interested":
        add_notification(
            candidate_id,
            f"{current_user['name']} sent you a SkillSwap connection request.",
            url_for("connections")
        )
        add_activity(
            current_user["_id"],
            "Connection request sent",
            f"You are interested in exchanging skills with {candidate['name']}.",
            url_for("connections")
        )

    message = (
        f"Connection request sent to {candidate['name']}."
        if action == "interested"
        else "Match passed."
    )

    return jsonify({"message": message})


@app.route("/matches/undo-pass", methods=["POST"])
def undo_match_pass():

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    last_pass = matches_collection.find_one(
        {
            "from_user_id": current_user_id,
            "action": "pass",
            "status": "passed"
        },
        sort=[("updated_at", -1)]
    )

    if last_pass:
        matches_collection.update_one(
            {"_id": last_pass["_id"]},
            {
                "$set": {
                    "status": "undone",
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

    return redirect(url_for("matches"))


@app.route("/connections")
def connections():

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})

    received_connections = []
    for connection in matches_collection.find({
        "to_user_id": current_user_id,
        "action": "interested",
        "status": "pending"
    }):
        connection = dict(connection)
        connection["user"] = users_collection.find_one({
            "_id": connection["from_user_id"]
        })
        received_connections.append(connection)

    sent_connections = []
    for connection in matches_collection.find({
        "from_user_id": current_user_id,
        "action": "interested",
        "status": "pending"
    }):
        connection = dict(connection)
        connection["user"] = users_collection.find_one({
            "_id": connection["to_user_id"]
        })
        sent_connections.append(connection)

    active_exchanges = []
    for connection in matches_collection.find({
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    }):
        connection = dict(connection)
        partner_id = (
            connection["to_user_id"]
            if connection["from_user_id"] == current_user_id
            else connection["from_user_id"]
        )
        connection["partner"] = users_collection.find_one({"_id": partner_id})
        connection["last_message"] = messages_collection.find_one(
            {"connection_id": connection["_id"]},
            sort=[("sent_at", -1)]
        )
        connection["partner_reputation"] = get_user_reputation(partner_id)
        connection["progress"] = get_exchange_progress(connection, current_user)
        connection["completion_confirmed_by_me"] = (
            current_user_id in connection.get("completion_confirmed_by", [])
        )
        connection["completion_confirmations"] = len(
            connection.get("completion_confirmed_by", [])
        )
        active_exchanges.append(connection)

    completed_exchanges = []
    for connection in matches_collection.find({
        "action": "interested",
        "status": "completed",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    }):
        connection = dict(connection)
        partner_id = (
            connection["to_user_id"]
            if connection["from_user_id"] == current_user_id
            else connection["from_user_id"]
        )
        connection["partner"] = users_collection.find_one({"_id": partner_id})
        connection["partner_reputation"] = get_user_reputation(partner_id)
        connection["my_review"] = reviews_collection.find_one({
            "connection_id": connection["_id"],
            "reviewer_id": current_user_id
        })
        completed_exchanges.append(connection)

    return render_template(
        "connections.html",
        received_connections=received_connections,
        sent_connections=sent_connections,
        active_exchanges=active_exchanges,
        completed_exchanges=completed_exchanges,
        notice=request.args.get("notice")
    )


@app.route("/leaderboard")
def leaderboard():
    """Show this week's confirmed learning-exchange activity."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    weekly_leaderboard, week_start, week_end = get_weekly_leaderboard()

    return render_template(
        "leaderboard.html",
        leaderboard=weekly_leaderboard,
        week_start=week_start,
        week_end=week_end
    )


@app.route("/schedule")
def schedule():
    """Show a simple calendar-style view of the user's active exchange plans."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})
    week_start = datetime.now().date() - timedelta(days=datetime.now().weekday())
    calendar_days = [week_start + timedelta(days=offset) for offset in range(7)]
    schedule_items = {day.isoformat(): [] for day in calendar_days}

    connections = matches_collection.find({
        "action": "interested",
        "status": "accepted",
        "$or": [{"from_user_id": current_user_id}, {"to_user_id": current_user_id}]
    })
    for connection in connections:
        partner_id = (
            connection["to_user_id"]
            if connection["from_user_id"] == current_user_id
            else connection["from_user_id"]
        )
        partner = users_collection.find_one({"_id": partner_id})
        if not partner:
            continue
        for slot in connection.get("timetable", []):
            for day in calendar_days:
                if day.strftime("%A") in slot.get("days", []):
                    schedule_items[day.isoformat()].append({
                        "time": slot.get("start_time", ""),
                        "skill": slot.get("skill", "Skill exchange"),
                        "partner": partner["name"],
                        "is_teaching": slot.get("teacher_id") == current_user_id,
                        "connection_id": connection["_id"]
                    })

    for items in schedule_items.values():
        items.sort(key=lambda item: item["time"])

    return render_template(
        "schedule.html",
        calendar_days=calendar_days,
        schedule_items=schedule_items,
        today_date=datetime.now().date(),
        current_user=current_user
    )


@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    notification_list = list(
        notifications_collection.find({"user_id": current_user_id})
        .sort("created_at", -1)
        .limit(50)
    )
    notifications_collection.update_many(
        {"user_id": current_user_id, "is_read": False},
        {"$set": {"is_read": True}}
    )
    return render_template("notifications.html", notifications=notification_list)


@app.route("/api/session-reminders")
def session_reminders_status():
    """Let an open SkillSwap page refresh its notification count each minute."""
    if "user_id" not in session or not ObjectId.is_valid(session["user_id"]):
        return jsonify({"unread": 0, "rating_prompts": []})

    current_user_id = ObjectId(session["user_id"])
    rating_prompts = list(
        notifications_collection.find({
            "user_id": current_user_id,
            "is_read": False,
            "type": "session_rating"
        }).sort("created_at", -1).limit(5)
    )
    return jsonify({
        "unread": notifications_collection.count_documents({
            "user_id": current_user_id,
            "is_read": False
        }),
        "rating_prompts": [
            {
                "id": str(prompt["_id"]),
                "message": prompt["message"],
                "link": prompt.get("link")
            }
            for prompt in rating_prompts
        ]
    })


@app.route("/activity")
def activity_history():
    if "user_id" not in session:
        return redirect(url_for("login"))

    activity_items = list(
        activities_collection.find({"user_id": ObjectId(session["user_id"])})
        .sort("created_at", -1)
        .limit(50)
    )
    return render_template("activity.html", activity_items=activity_items)


@app.route("/connections/<connection_id>/<decision>", methods=["POST"])
def connection_decision(connection_id, decision):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if decision not in ["accept", "reject"]:
        return redirect(url_for("connections"))

    new_status = "accepted" if decision == "accept" else "rejected"

    if not ObjectId.is_valid(connection_id):
        return redirect(url_for("connections"))

    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "to_user_id": ObjectId(session["user_id"]),
        "action": "interested",
        "status": "pending"
    })
    if not connection:
        return redirect(url_for("connections"))

    matches_collection.update_one(
        {
            "_id": ObjectId(connection_id),
            "to_user_id": ObjectId(session["user_id"]),
            "action": "interested",
            "status": "pending"
        },
        {
            "$set": {
                "status": new_status,
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )

    current_user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if decision == "accept":
        add_notification(
            connection["from_user_id"],
            f"{current_user['name']} accepted your SkillSwap request. Start planning your exchange.",
            url_for("chat", connection_id=connection["_id"])
        )
        add_activity(
            current_user["_id"],
            "Connection accepted",
            f"You can now exchange skills with the new connection.",
            url_for("chat", connection_id=connection["_id"])
        )

    return redirect(url_for("connections"))


@app.route("/connections/<connection_id>/complete", methods=["POST"])
def complete_exchange(connection_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    connection = matches_collection.find_one(
        {
            "_id": ObjectId(connection_id),
            "action": "interested",
            "status": "accepted",
            "$or": [
                {"from_user_id": current_user_id},
                {"to_user_id": current_user_id}
            ]
        }
    )

    if not connection:
        return redirect(url_for("connections"))

    matches_collection.update_one(
        {"_id": connection["_id"]},
        {"$addToSet": {"completion_confirmed_by": current_user_id}}
    )
    connection = matches_collection.find_one({"_id": connection["_id"]})
    both_confirmed = {
        connection["from_user_id"], connection["to_user_id"]
    }.issubset(set(connection.get("completion_confirmed_by", [])))

    if both_confirmed:
        matches_collection.update_one(
            {"_id": connection["_id"]},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        notice = "Both partners confirmed completion. Your exchange certificates are ready."
    else:
        notice = "Your completion confirmation was saved. Waiting for your partner."

    return redirect(url_for("connections", notice=notice))


@app.route("/rate/<connection_id>", methods=["GET", "POST"])
def rate_exchange(connection_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})

    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))

    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "completed",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })

    if not connection:
        return redirect(url_for("connections"))

    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    partner = users_collection.find_one({"_id": partner_id})
    existing_review = reviews_collection.find_one({
        "connection_id": connection["_id"],
        "reviewer_id": current_user_id,
        "review_kind": {"$ne": "session"}
    })

    if request.method == "POST":
        try:
            rating = int(request.form.get("rating", 0))
        except ValueError:
            rating = 0

        comment = request.form.get("comment", "").strip()

        if rating not in range(1, 6):
            return render_template(
                "rate_exchange.html",
                connection=connection,
                partner=partner,
                existing_review=existing_review,
                error="Please choose a rating from 1 to 5 stars."
            )

        reviews_collection.update_one(
            {
                "connection_id": connection["_id"],
                "reviewer_id": current_user_id,
                "review_kind": {"$ne": "session"}
            },
            {
                "$set": {
                    "connection_id": connection["_id"],
                    "reviewer_id": current_user_id,
                    "reviewed_user_id": partner_id,
                    "review_kind": "exchange",
                    "rating": rating,
                    "comment": comment[:500],
                    "updated_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )

        return redirect(url_for("connections"))

    return render_template(
        "rate_exchange.html",
        connection=connection,
        partner=partner,
        existing_review=existing_review
    )


@app.route("/session-rate/<session_id>", methods=["GET", "POST"])
def rate_session(session_id):
    """Let each participant review their partner after one scheduled session."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not ObjectId.is_valid(session_id):
        return redirect(url_for("notifications"))

    current_user_id = ObjectId(session["user_id"])
    scheduled_session = sessions_collection.find_one({"_id": ObjectId(session_id)})
    if not scheduled_session:
        return redirect(url_for("notifications"))

    connection = matches_collection.find_one({
        "_id": scheduled_session["connection_id"],
        "action": "interested",
        "status": {"$in": ["accepted", "completed"]},
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })
    if not connection:
        return redirect(url_for("notifications"))

    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    partner = users_collection.find_one({"_id": partner_id})
    existing_review = reviews_collection.find_one({
        "session_id": scheduled_session["_id"],
        "reviewer_id": current_user_id,
        "review_kind": "session"
    })

    if request.method == "POST":
        try:
            rating = int(request.form.get("rating", 0))
        except ValueError:
            rating = 0
        comment = request.form.get("comment", "").strip()

        if rating not in range(1, 6):
            return render_template(
                "rate_session.html",
                scheduled_session=scheduled_session,
                partner=partner,
                existing_review=existing_review,
                error="Choose a rating from 1 to 5 before submitting."
            )
        if not comment:
            return render_template(
                "rate_session.html",
                scheduled_session=scheduled_session,
                partner=partner,
                existing_review=existing_review,
                error="Please tell us how your experience was."
            )

        reviews_collection.update_one(
            {
                "session_id": scheduled_session["_id"],
                "reviewer_id": current_user_id,
                "review_kind": "session"
            },
            {"$set": {
                "session_id": scheduled_session["_id"],
                "connection_id": connection["_id"],
                "reviewer_id": current_user_id,
                "reviewed_user_id": partner_id,
                "review_kind": "session",
                "rating": rating,
                "comment": comment[:500],
                "updated_at": datetime.now(timezone.utc)
            }},
            upsert=True
        )
        add_notification(
            partner_id,
            f"{session.get('user_name', 'Your partner')} shared session feedback.",
            url_for("chat", connection_id=connection["_id"])
        )
        add_activity(
            current_user_id,
            "Session rating submitted",
            f"You rated your {scheduled_session.get('skill', 'SkillSwap')} session with {partner['name']}."
        )
        return redirect(url_for("notifications"))

    return render_template(
        "rate_session.html",
        scheduled_session=scheduled_session,
        partner=partner,
        existing_review=existing_review
    )


@app.route("/chat/<connection_id>/timetable", methods=["POST"])
def save_timetable(connection_id):
    """Save the current user's teaching sessions for an active exchange."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})
    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))

    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })

    if not connection:
        return redirect(url_for("connections"))

    days = [day for day in request.form.getlist("days") if day in WEEKDAYS]
    start_time = request.form.get("start_time", "")
    try:
        duration_minutes = int(request.form.get("duration_minutes", "0"))
    except ValueError:
        duration_minutes = 0

    if not days or not start_time or duration_minutes not in [30, 60, 90, 120]:
        return redirect(url_for(
            "chat",
            connection_id=connection_id,
            notice="Choose at least one weekday, a start time, and a session duration."
        ))

    own_slot = {
        "teacher_id": current_user_id,
        "skill": current_user["teach_skill"],
        "days": days,
        "start_time": start_time,
        "duration_minutes": duration_minutes
    }
    timetable = [
        slot for slot in connection.get("timetable", [])
        if slot.get("teacher_id") != current_user_id
    ]
    timetable.append(own_slot)

    # A changed timetable must be agreed by both people again.
    matches_collection.update_one(
        {"_id": connection["_id"]},
        {"$set": {
            "timetable": timetable,
            "timetable_confirmed_by": [],
            "timetable_updated_at": datetime.now(timezone.utc)
        }}
    )

    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    add_notification(
        partner_id,
        f"{current_user['name']} updated their teaching timetable. Please review it.",
        url_for("chat", connection_id=connection["_id"])
    )
    add_activity(
        current_user_id,
        "Teaching timetable updated",
        "Your shared exchange schedule now needs confirmation.",
        url_for("chat", connection_id=connection["_id"])
    )

    return redirect(url_for(
        "chat",
        connection_id=connection_id,
        notice="Your teaching timetable was saved. Both partners must confirm the combined plan."
    ))


@app.route("/chat/<connection_id>/goal", methods=["POST"])
def save_exchange_goal(connection_id):
    """Save one partner's goal for an active learning exchange."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(connection_id):
        return redirect(url_for("connections"))

    current_user_id = ObjectId(session["user_id"])
    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })
    goal_text = request.form.get("goal", "").strip()

    if not connection or not goal_text:
        return redirect(url_for(
            "chat",
            connection_id=connection_id,
            notice="Write a short exchange goal before saving it."
        ))

    goals = [
        goal for goal in connection.get("exchange_goals", [])
        if goal.get("user_id") != current_user_id
    ]
    goals.append({
        "user_id": current_user_id,
        "goal": goal_text[:300],
        "updated_at": datetime.now(timezone.utc)
    })
    matches_collection.update_one(
        {"_id": connection["_id"]},
        {"$set": {"exchange_goals": goals, "updated_at": datetime.now(timezone.utc)}}
    )

    return redirect(url_for(
        "chat",
        connection_id=connection_id,
        notice="Your exchange goal was saved."
    ))


@app.route("/chat/<connection_id>/confirm-timetable", methods=["POST"])
def confirm_timetable(connection_id):
    """Record one partner's confirmation of the full timetable."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})
    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))

    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })

    if not connection or not timetable_is_ready(connection):
        return redirect(url_for(
            "chat",
            connection_id=connection_id,
            notice="Both partners need to add their teaching timetable first."
        ))

    matches_collection.update_one(
        {"_id": connection["_id"]},
        {"$addToSet": {"timetable_confirmed_by": current_user_id}}
    )

    return redirect(url_for(
        "chat",
        connection_id=connection_id,
        notice="Your timetable confirmation was saved."
    ))


@app.route("/chat/<connection_id>/sessions/<teacher_id>/confirm", methods=["POST"])
def confirm_session(connection_id, teacher_id):
    """Let each partner confirm a scheduled teaching session for today."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})
    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))

    teacher_object_id = ObjectId(teacher_id)
    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": "accepted",
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })

    if not connection or not timetable_is_confirmed(connection):
        return redirect(url_for("connections"))

    timetable_slot = get_timetable_slot(connection, teacher_object_id)
    today = datetime.now().strftime("%A")
    session_date = datetime.now().date().isoformat()

    if not timetable_slot or today not in timetable_slot.get("days", []):
        return redirect(url_for(
            "chat",
            connection_id=connection_id,
            notice="This session is not scheduled for today."
        ))

    session_key = {
        "connection_id": connection["_id"],
        "teacher_id": teacher_object_id,
        "session_date": session_date,
        "start_time": timetable_slot["start_time"]
    }
    existing_session = sessions_collection.find_one(session_key)

    if existing_session and current_user_id in existing_session.get("confirmed_by", []):
        return redirect(url_for(
            "chat",
            connection_id=connection_id,
            notice="You already confirmed this session."
        ))

    sessions_collection.update_one(
        session_key,
        {
            "$setOnInsert": {
                **session_key,
                "skill": timetable_slot["skill"],
                "start_time": timetable_slot["start_time"],
                "duration_minutes": timetable_slot["duration_minutes"],
                "created_at": datetime.now(timezone.utc)
            },
            "$addToSet": {"confirmed_by": current_user_id}
        },
        upsert=True
    )
    confirmed_session = sessions_collection.find_one(session_key)
    both_confirmed = {
        connection["from_user_id"], connection["to_user_id"]
    }.issubset(set(confirmed_session.get("confirmed_by", [])))

    if both_confirmed:
        sessions_collection.update_one(
            {"_id": confirmed_session["_id"]},
            {"$set": {
                "status": "confirmed",
                "confirmed_at": datetime.now(timezone.utc)
            }}
        )
        for participant_id in [connection["from_user_id"], connection["to_user_id"]]:
            add_activity(
                participant_id,
                "Session completed",
                f"{timetable_slot['skill']} session confirmed by both partners.",
                url_for("chat", connection_id=connection["_id"])
            )
        notice = "Session confirmed by both partners — it now counts toward progress."
    else:
        notice = "Your completion confirmation was saved. Waiting for your partner."

    return redirect(url_for("chat", connection_id=connection_id, notice=notice))


@app.route("/chat/<connection_id>/report", methods=["POST"])
def report_connection(connection_id):
    """Store a private safety report from one participant in an exchange."""
    if "user_id" not in session or not ObjectId.is_valid(connection_id):
        return redirect(url_for("connections"))

    current_user_id = ObjectId(session["user_id"])
    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "$or": [{"from_user_id": current_user_id}, {"to_user_id": current_user_id}]
    })
    if not connection:
        return redirect(url_for("connections"))

    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )

    report_type = request.form.get("report_type", "Other")[:60]
    details = request.form.get("details", "").strip()[:1000]
    if not details:
        return redirect(url_for("chat", connection_id=connection_id, notice="Please describe the safety concern before submitting."))

    reports_collection.insert_one({
        "connection_id": connection["_id"],
        "reported_by": current_user_id,
        "reported_user_id": partner_id,
        "report_type": report_type,
        "details": details,
        "status": "open",
        "created_at": datetime.now(timezone.utc)
    })
    add_activity(current_user_id, "Safety report submitted", "Your report was saved privately for review.")
    return redirect(url_for("chat", connection_id=connection_id, notice="Your report was submitted privately. Thank you for helping keep SkillSwap safe."))


@app.route("/chat/<connection_id>", methods=["GET", "POST"])
def chat(connection_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # A chat URL must contain a real MongoDB connection ID.
    # Redirect safely if someone types a placeholder or invalid link.
    if not ObjectId.is_valid(connection_id):
        return redirect(url_for("connections"))

    current_user_id = ObjectId(session["user_id"])
    current_user = users_collection.find_one({"_id": current_user_id})

    if not is_user_ready_to_exchange(current_user):
        return redirect(url_for("verify_skill"))
    connection = matches_collection.find_one({
        "_id": ObjectId(connection_id),
        "action": "interested",
        "status": {"$in": ["accepted", "completed"]},
        "$or": [
            {"from_user_id": current_user_id},
            {"to_user_id": current_user_id}
        ]
    })

    # Chat is available only to the two users in an accepted connection.
    if not connection:
        return redirect(url_for("connections"))

    partner_id = (
        connection["to_user_id"]
        if connection["from_user_id"] == current_user_id
        else connection["from_user_id"]
    )
    partner = users_collection.find_one({"_id": partner_id})

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()

        if message_text:
            messages_collection.insert_one({
                "connection_id": connection["_id"],
                "sender_id": current_user_id,
                "receiver_id": partner_id,
                "message": message_text[:1000],
                "sent_at": datetime.now(timezone.utc)
            })
            add_notification(
                partner_id,
                f"New message from {current_user['name']}.",
                url_for("chat", connection_id=connection["_id"])
            )
            add_activity(
                current_user_id,
                "Message sent",
                f"You messaged {partner['name']}.",
                url_for("chat", connection_id=connection["_id"])
            )

        return redirect(url_for("chat", connection_id=connection_id))

    conversation = list(
        messages_collection.find({"connection_id": connection["_id"]})
        .sort("sent_at", 1)
    )

    for message in conversation:
        message["is_mine"] = message["sender_id"] == current_user_id

    today = datetime.now().strftime("%A")
    exchange_goals = []
    for goal in connection.get("exchange_goals", []):
        display_goal = dict(goal)
        display_goal["owner"] = (
            current_user if goal["user_id"] == current_user_id else partner
        )
        display_goal["is_mine"] = goal["user_id"] == current_user_id
        exchange_goals.append(display_goal)

    timetable_slots = []
    for slot in connection.get("timetable", []):
        display_slot = dict(slot)
        display_slot["teacher"] = (
            current_user if slot["teacher_id"] == current_user_id else partner
        )
        display_slot["is_my_teaching"] = slot["teacher_id"] == current_user_id
        display_slot["is_scheduled_today"] = today in slot.get("days", [])
        timetable_slots.append(display_slot)

    session_history = list(
        sessions_collection.find({"connection_id": connection["_id"]})
        .sort("session_date", -1)
        .limit(10)
    )
    for scheduled_session in session_history:
        scheduled_session["teacher"] = (
            current_user
            if scheduled_session["teacher_id"] == current_user_id
            else partner
        )
        scheduled_session["is_confirmed"] = scheduled_session.get("status") == "confirmed"
        scheduled_session["confirmed_by_me"] = (
            current_user_id in scheduled_session.get("confirmed_by", [])
        )

    return render_template(
        "chat.html",
        connection=connection,
        partner=partner,
        conversation=conversation,
        current_user=current_user,
        weekdays=WEEKDAYS,
        today=today,
        exchange_goals=exchange_goals,
        my_exchange_goal=get_exchange_goal(connection, current_user_id),
        timetable_slots=timetable_slots,
        my_timetable_slot=get_timetable_slot(connection, current_user_id),
        timetable_ready=timetable_is_ready(connection),
        timetable_confirmed=timetable_is_confirmed(connection),
        timetable_confirmed_by_me=(
            current_user_id in connection.get("timetable_confirmed_by", [])
        ),
        session_history=session_history,
        notice=request.args.get("notice")
    )


@app.route("/logout", methods=["POST"])
def logout():

    # Remove the saved login information
    session.clear()

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
