from pymongo import MongoClient

# Connect to local MongoDB
client = MongoClient("mongodb://127.0.0.1:27017/")

# SkillSwap database
db = client["skillswap_db"]

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
