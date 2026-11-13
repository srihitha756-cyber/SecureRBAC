"""SecureRBAC launcher: migrates/creates SQLite (instance/rbac.db), seeds users only if missing, trains ML if needed, starts Flask."""
import os
from app import create_app
from app.seed import seed
app = create_app()           # normal startup: login required (no auto-login code exists)
made = seed(app)
if made:
    print("Database ready. Accounts created: " + ", ".join(made) + "  (demo admin: admin / admin@12345; others have random passwords)")
    for u, p in made.items():
        if u != "admin": print("   %-10s %s" % (u, p))
if not os.path.exists(os.path.join("ml", "models", "model.joblib")):
    from ml.engine import train; train(); print("ML model trained (synthetic data).")
if __name__ == "__main__":
    print("Open http://127.0.0.1:5000"); app.run(host="127.0.0.1", port=5000, debug=False)
