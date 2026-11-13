"""python -m scripts.setup_db -> create/migrate instance/rbac.db and seed users if missing (existing passwords are never overwritten)."""
from app import create_app
from app.seed import seed
app = create_app(); made = seed(app)
print("Database:", app.config["DB"]); print("Created:", ", ".join(made) if made else "nothing (already seeded)")
for u, p in made.items():
    if u != "admin": print("  %-10s %s" % (u, p))
