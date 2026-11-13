"""Run: python -m pytest -v   (or python -m unittest discover -v). Uses an isolated temp database."""
import os, tempfile, unittest, hashlib, sqlite3
from app import create_app, totp
from app.seed import seed
from app.lab import SimClient, SIMS, VULN, run_sims

class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(); cls.app = create_app({"DB": os.path.join(cls.dir, "t.db"), "TESTING": True}); cls.pw = seed(cls.app)
    def login(self, user, ip="10.0.0.1", ua="UA1"):
        c = SimClient(self.app, ip, ua); r = c.req("post", "/api/login", {"username": user, "password": self.pw[user]}); return c, r
    def q(self, sql, a=()): c = self.app.connect(); r = c.execute(sql, a).fetchall(); c.close(); return r

class TestAuthRBAC(Base):
    def test_password_is_hashed(self): self.assertNotIn(self.pw["admin1"], self.q("SELECT pw_hash FROM users WHERE username='admin1'")[0][0]); self.assertTrue(self.q("SELECT pw_hash FROM users WHERE username='admin1'")[0][0].startswith(("$argon2id", "scrypt$")))
    def test_valid_login_and_unauth_401(self):
        self.assertEqual(self.login("employee1")[1].status_code, 200); self.assertEqual(self.app.test_client().get("/api/users").status_code, 401)
    def test_rbac_matrix(self):
        e, _ = self.login("employee1", "10.0.0.2"); a, _ = self.login("admin1", "10.0.0.3"); m, _ = self.login("manager1", "10.0.0.4")
        self.assertEqual(e.req("get", "/api/users").status_code, 403); self.assertEqual(m.req("get", "/api/users").status_code, 200)   # manager has VIEW_USERS
        self.assertEqual(a.req("get", "/api/users").status_code, 200)                                                             # admin inherits it (hierarchy)
        self.assertEqual(m.req("get", "/api/audit").status_code, 403)
    def test_csrf_required(self):
        c = self.app.test_client(); self.assertEqual(c.post("/api/logout").status_code, 403)
    def test_session_fixation_new_sid(self):
        c = SimClient(self.app, "10.0.0.5"); before = c.c.get_cookie("rbac_session").value; c.req("post", "/api/login", {"username": "employee1", "password": self.pw["employee1"]}); self.assertNotEqual(before, c.c.get_cookie("rbac_session").value)
    def test_cookie_flags(self):
        c = SimClient(self.app, "10.0.0.6"); self.assertTrue(c.c.get_cookie("rbac_session").http_only)
    def test_sql_injection_login(self):
        r = SimClient(self.app, "10.0.0.7").req("post", "/api/login", {"username": "' OR 1=1 --", "password": "' OR '1'='1"}); self.assertEqual(r.status_code, 401)
    def test_xss_stored_as_text_and_rejected(self):
        r = SimClient(self.app, "10.0.0.8").req("post", "/api/register", {"username": "<script>x</script>", "full_name": "Xx Yy", "email": "a@b.co", "password": "Str0ng#Passw0rd", "confirm": "Str0ng#Passw0rd"}); self.assertEqual(r.status_code, 400)
    def test_weak_password_rejected(self): self.assertEqual(SimClient(self.app, "10.0.0.9").req("post", "/api/register", {"username": "weakling", "email": "a@b.co", "password": "password"}).status_code, 400)
    def test_idor_admin_cannot_delete_higher_role(self):
        a, _ = self.login("admin1", "10.0.0.10"); sid = self.q("SELECT id FROM users WHERE username='superadmin'")[0][0]
        self.assertEqual(a.req("delete", "/api/users/%d" % sid).status_code, 403); self.assertEqual(len(self.q("SELECT 1 FROM users WHERE id=?", (sid,))), 1)
    def test_mfa_flow(self):
        c, _ = self.login("analyst1", "10.0.0.11"); s = c.req("post", "/api/mfa/enroll").json["secret"]; self.assertEqual(c.req("post", "/api/mfa/confirm", {"code": totp(s)}).status_code, 200)
        c2 = SimClient(self.app, "10.0.0.11"); self.assertEqual(c2.req("post", "/api/login", {"username": "analyst1", "password": self.pw["analyst1"]}).status_code, 202)
        self.assertEqual(c2.req("post", "/api/login/mfa", {"code": "000000"}).status_code, 401); self.assertEqual(c2.req("post", "/api/login/mfa", {"code": totp(s)}).status_code, 200)

class TestDatabase(Base):
    def test_fk_enforced(self):
        c = self.app.connect()
        with self.assertRaises(sqlite3.IntegrityError): c.execute("INSERT INTO users(username,email,pw_hash,role_id,created_at) VALUES('z','z','z',9999,'x')")
        c.close()
    def test_audit_append_only_and_tamper_detected(self):
        self.login("manager1", "10.0.1.1"); c = self.app.connect()
        with self.assertRaises(sqlite3.DatabaseError): c.execute("UPDATE audit_logs SET outcome='x'")
        with self.assertRaises(sqlite3.DatabaseError): c.execute("DELETE FROM audit_logs")
        c.execute("DROP TRIGGER audit_no_update"); c.execute("UPDATE audit_logs SET outcome='FORGED' WHERE id=1"); c.commit()   # attacker with raw DB access
        s, _ = self.login("analyst1", "10.0.1.2")
        v = s.req("get", "/api/audit/verify"); self.assertFalse(v.json["valid"]); c.close()
    def test_persistence_across_restart(self):
        app2 = create_app({"DB": self.app.config["DB"]}); c = app2.connect(); self.assertGreater(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 4)

class TestAttackSimulations(Base):   # the four mandatory threats, re-run against the live defenses
    def _run(self, name):
        r = SIMS[name](self.app); bad = [c for c in r["checks"] if not c["passed"]]; self.assertEqual(bad, [], bad)
    def test_brute_force(self): self._run("brute_force")
    def test_privilege_escalation(self): self._run("privilege_escalation")
    def test_account_takeover(self): self._run("account_takeover")
    def test_role_tampering(self): self._run("role_tampering")
    def test_rerun_second_time_still_blocked(self):    # "test again with the same threats": defenses hold on repeat
        for n in SIMS: self._run(n)

class TestDemoAndComparison(Base):
    def test_demo_admin_login_and_no_plaintext(self):
        c = SimClient(self.app, "10.2.0.1"); r = c.req("post", "/api/login", {"username": "admin", "password": "admin@12345"}); self.assertEqual(r.status_code, 200)
        self.assertNotIn("admin@12345", self.q("SELECT pw_hash FROM users WHERE username='admin'")[0][0])
    def test_seed_idempotent_keeps_admin_password(self):
        h = self.q("SELECT pw_hash FROM users WHERE username='admin'")[0][0]; seed(self.app); self.assertEqual(h, self.q("SELECT pw_hash FROM users WHERE username='admin'")[0][0])
    def test_registration_full_flow_and_role(self):
        c = SimClient(self.app, "10.2.0.2"); pw = "Regist#r1ation9"
        r = c.req("post", "/api/register", {"full_name": "Asha Rao", "username": "asha", "email": "asha@x.io", "password": pw, "confirm": pw, "role": "Super Admin"}); self.assertEqual(r.status_code, 201)
        self.assertEqual(self.q("SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE username='asha'")[0][0], "Employee")
        self.assertEqual(c.req("post", "/api/register", {"full_name": "Asha Rao", "username": "asha", "email": "a@x.io", "password": pw, "confirm": pw}).status_code, 409)
        self.assertEqual(c.req("post", "/api/register", {"full_name": "A B", "username": "asha2", "email": "a@x.io", "password": pw, "confirm": "nope"}).status_code, 400)
    def test_vulnerable_baseline_shows_compromise_for_all_four(self):
        for n, f in VULN.items(): r = f(); self.assertTrue(r["passed"], (n, r["checks"])); self.assertEqual(r["outcome"], "SIMULATED COMPROMISE")
    def test_vulnerable_baseline_touches_nothing_real(self):
        b = self.q("SELECT COUNT(*) FROM users")[0][0]; [f() for f in VULN.values()]; self.assertEqual(b, self.q("SELECT COUNT(*) FROM users")[0][0])
    def test_both_mode_repeatable_and_measured_rate(self):
        for _ in range(2):
            o = run_sims(self.app, "both", 1); s = o["summary"]; self.assertEqual(s["checks_passed"], s["checks_total"]); self.assertEqual(s["protection_rate"], 100.0); self.assertEqual(s["baseline_compromised"], 4)
            self.assertEqual([r["protected"]["outcome"] for r in o["rows"]], ["BLOCKED", "DENIED", "RESTRICTED / MFA", "REJECTED"])
    def test_sim_endpoints_require_permission_and_clear_keeps_audit(self):
        e, _ = self.login("employee1", "10.2.0.3"); self.assertEqual(e.req("post", "/api/sim/run", {"mode": "both"}).status_code, 403)
        a, _ = self.login("admin", "10.2.0.4", "UA9") if False else (SimClient(self.app, "10.2.0.4"), 0); a.req("post", "/api/login", {"username": "admin", "password": "admin@12345"})
        a.req("post", "/api/sim/run", {"mode": "vulnerable"}); n = self.q("SELECT COUNT(*) FROM audit_logs")[0][0]; self.assertEqual(a.req("post", "/api/sim/clear").status_code, 200)
        self.assertEqual(self.q("SELECT COUNT(*) FROM simulation_runs")[0][0], 0); self.assertGreaterEqual(self.q("SELECT COUNT(*) FROM audit_logs")[0][0], n)
    def test_policy_verify_dashboard_reports(self):
        a = SimClient(self.app, "10.2.0.5"); a.req("post", "/api/login", {"username": "admin", "password": "admin@12345"})
        self.assertTrue(a.req("get", "/api/policy/verify").json["passed"]); d = a.req("get", "/api/dashboard").json; self.assertEqual(d["total_users"], self.q("SELECT COUNT(*) FROM users")[0][0])
        for u in ("/api/monitor", "/api/report.csv", "/api/report.pdf", "/api/ml/metrics"): self.assertEqual(a.req("get", u).status_code, 200, u)
    def test_old_db_migration_with_backup(self):
        import sqlite3 as s3; p = os.path.join(tempfile.mkdtemp(), "old.db"); c = s3.connect(p); c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT, pw_hash TEXT, role_id INTEGER, active INTEGER, failed_count INTEGER, locked_until TEXT, mfa_secret TEXT, mfa_pending TEXT, mfa_enabled INTEGER, created_at TEXT, last_login TEXT)")
        c.execute("INSERT INTO users(username) VALUES('legacy')"); c.commit(); c.close(); create_app({"DB": p}); self.assertEqual(s3.connect(p).execute("SELECT username FROM users").fetchone()[0], "legacy")
        self.assertTrue(any(".bak-" in f for f in os.listdir(os.path.dirname(p))))

if __name__ == "__main__": unittest.main()
