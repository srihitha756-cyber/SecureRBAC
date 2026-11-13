import os, secrets, string
from . import ROLES, PERMS, ROLE_PERMS, hash_pw, now, policy_hash
DEMO_ADMIN_PW = os.environ.get("DEMO_ADMIN_PASSWORD", "admin@12345")   # local classroom demo only - set a strong secret for real deployments

def rand_pw():
    a = string.ascii_letters + string.digits
    return "".join(secrets.choice(a) for _ in range(12)) + "#9aZ"

def seed(app, admin_password=None, demo=True):
    """Idempotent: creates roles, permissions, role->permission links and (optionally) demo accounts. Returns {user: password} for NEW users only."""
    c = app.connect(); made = {}
    for n, l in ROLES: c.execute("INSERT OR IGNORE INTO roles(name,level) VALUES(?,?)", (n, l))
    for p in PERMS: c.execute("INSERT OR IGNORE INTO permissions(name) VALUES(?)", (p,))
    for r, ps in ROLE_PERMS.items():
        for p in ps: c.execute("INSERT OR IGNORE INTO role_permissions SELECT r.id,p.id FROM roles r,permissions p WHERE r.name=? AND p.name=?", (r, p))
    users = [("admin", "Administrator", DEMO_ADMIN_PW), ("superadmin", "Super Admin", admin_password)] + ([("admin1", "Administrator", None), ("analyst1", "Security Analyst", None), ("manager1", "Manager", None), ("employee1", "Employee", None)] if demo else [])
    for un, role, pw in users:
        if not c.execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone():
            pw = pw or rand_pw()
            c.execute("INSERT INTO users(username,full_name,email,pw_hash,role_id,created_at) SELECT ?,?,?,?,id,? FROM roles WHERE name=?", (un, un.title(), un + "@securerbac.local", hash_pw(pw), now(), role)); made[un] = pw
    if not c.execute("SELECT 1 FROM security_policy_versions").fetchone(): c.execute("INSERT INTO security_policy_versions(ts,policy_hash,note) VALUES(?,?,?)", (now(), policy_hash(c), "initial seeded policy"))
    c.commit(); c.close(); return made
