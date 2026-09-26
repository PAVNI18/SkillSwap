"""MongoDB connection shared by the SkillSwap application.

Local development uses MongoDB on the computer. Deployment uses the
``MONGODB_URI`` environment variable, which can contain a MongoDB Atlas
``mongodb+srv://`` connection string. The URI is deliberately never stored in
source control.
"""

import os

import certifi
from pymongo import MongoClient


MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017/")
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "skillswap_db")

# The client connects lazily. Timeouts keep a misconfigured deployment from
# hanging requests for an unnecessarily long time.
mongo_options = {
    "serverSelectionTimeoutMS": 5000,
    "connectTimeoutMS": 5000,
    "appname": "SkillSwap",
}

# Atlas uses TLS. On some local Python installations the operating-system
# certificate store is incomplete, so use certifi's maintained CA bundle.
if MONGODB_URI.startswith("mongodb+srv://"):
    mongo_options["tlsCAFile"] = certifi.where()

client = MongoClient(MONGODB_URI, **mongo_options)

# SkillSwap database
db = client[MONGODB_DB_NAME]

# Collections
users_collection = db["users"]
skills_collection = db["skills"]
matches_collection = db["matches"]
sessions_collection = db["sessions"]
messages_collection = db["messages"]
reviews_collection = db["reviews"]
badges_collection = db["badges"]
notifications_collection = db["notifications"]
activities_collection = db["activities"]
reports_collection = db["reports"]
