"""Create ten safe, repeatable learner profiles for the SkillSwap college demo.

Run with: python3 seed_demo_profiles.py
The profiles use the @skillswap.local address range and are never real people.
"""

from datetime import datetime, timezone

from models.database import users_collection


DEMO_PROFILES = (
    ("demo-card-01@skillswap.local", "Leena Kapoor", "Figma and wireframes", "8-9", "Beginner", "I enjoy turning rough ideas into clear, friendly app screens."),
    ("demo-card-02@skillswap.local", "Siddharth Rao", "Visual design systems", "Weekdays 6 PM - 8 PM", "Intermediate", "Let’s exchange practical web building and thoughtful interface design."),
    ("demo-card-03@skillswap.local", "Pooja Menon", "User research", "8-9", "Advanced", "I like testing ideas with people before turning them into polished designs."),
    ("demo-card-04@skillswap.local", "Neil Fernandes", "Responsive layouts", "Weekdays 6 PM - 8 PM", "Beginner", "I want to make websites more intuitive and accessible."),
    ("demo-card-05@skillswap.local", "Riya Bose", "Mobile app design", "8-9", "Intermediate", "I’m interested in learning how great designs become working web products."),
    ("demo-card-06@skillswap.local", "Om Patel", "Design prototyping", "8-9", "Advanced", "I build clickable prototypes and want to understand the code behind them."),
    ("demo-card-07@skillswap.local", "Ayesha Khan", "Colour and typography", "Weekdays 6 PM - 8 PM", "Beginner", "Help me bring my visual ideas to the web, and I’ll share design basics."),
    ("demo-card-08@skillswap.local", "Varun Sethi", "Accessibility design", "8-9", "Intermediate", "I care about making digital products easier for everyone to use."),
    ("demo-card-09@skillswap.local", "Priya Nair", "Interaction design", "Weekdays 6 PM - 8 PM", "Advanced", "I want to learn modern web development while sharing interface motion ideas."),
    ("demo-card-10@skillswap.local", "Aditya Roy", "Portfolio design", "8-9", "Beginner", "Let’s turn good projects into strong, easy-to-use online portfolios."),
)


def main():
    for email, name, focus, availability, skill_level, bio in DEMO_PROFILES:
        profile = {
            "name": name,
            "email": email,
            "role": "user",
            "is_demo": True,
            "teach_skill": "UI/UX",
            "learn_skill": "web development",
            "skill_level": skill_level,
            "availability": availability,
            "learning_duration": "3 Months",
            "bio": f"Demo profile · {focus}. {bio}",
            "onboarding_status": "completed",
        }
        update = {
            "$set": profile,
            "$setOnInsert": {"created_at": datetime.now(timezone.utc)},
        }
        if skill_level in {"Intermediate", "Advanced"}:
            update["$set"]["verification"] = {
                "skill": "UI/UX",
                "skill_level": skill_level,
                "passed": True,
                "verified_at": datetime.now(timezone.utc),
                "verification_method": "demo_seed",
            }
        else:
            update["$unset"] = {"verification": ""}
        users_collection.update_one(
            {"email": email},
            update,
            upsert=True,
        )
    print("10 SkillSwap demo learner profiles are ready.")


if __name__ == "__main__":
    main()
