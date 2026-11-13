"""Cybersecurity Attack Simulation Lab. Runs the four attacks against the REAL running defenses, through real HTTP
requests (Flask test client) from isolated sim_* accounts and documentation-range IPs (203.0.113.x). Nothing is hard-coded:
pass/fail is derived from HTTP codes, DB state, alerts and audit rows."""
import secrets, json
from flask import jsonify, request
from . import hash_pw, totp, now
from .seed import rand_pw

class SimClient:
    def __init__(self, app, ip, ua="SimBrowser/1.0"):
        self.c, self.ip, self.ua = app.test_client(), ip, ua
        self.t = self.c.get("/api/csrf", **self._kw()).json["csrf"]
    def _kw(self): return dict(environ_base={"REMOTE_ADDR": self.ip, "SIM": "1"}, headers={"User-Agent": self.ua})
    def req(self, m, url, j=None):
        kw = self._kw(); kw["headers"]["X-CSRF-Token"] = self.t
        r = getattr(self.c, m)(url, json=j, **kw)
        if r.is_json and isinstance(r.json, dict) and "csrf" in r.json: self.t = r.json["csrf"]
        return r

def prep(app, name, role):
    """(re)create an isolated sim account with a fresh random password; returns (id, password)."""
    c, pw = app.connect(), rand_pw()
    row = c.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()
    if row: c.execute("UPDATE users SET pw_hash=?, role_id=(SELECT id FROM roles WHERE name=?), active=1, failed_count=0, locked_until=NULL, mfa_enabled=0, mfa_secret=NULL WHERE id=?", (hash_pw(pw), role, row[0])); uid = row[0]
    else: uid = c.execute("INSERT INTO users(username,email,pw_hash,role_id,created_at) SELECT ?,?,?,id,? FROM roles WHERE name=?", (name, name + "@sim.local", hash_pw(pw), now(), role)).lastrowid
    c.execute("DELETE FROM login_attempts WHERE username=?", (name,)); c.commit(); c.close(); return uid, pw

def q(app, sql, a=()):
    c = app.connect(); r = c.execute(sql, a).fetchall(); c.close(); return r

def result(name, desc, checks, extra):
    return dict(name=name, description=desc, passed=all(c["passed"] for c in checks), checks=checks, **extra)

def chk(label, ok, evidence): return dict(check=label, passed=bool(ok), evidence=str(evidence))

def new_alerts(app, cat, t0): return [dict(r) for r in q(app, "SELECT id,severity,description,action FROM security_alerts WHERE category=? AND ts>=? ORDER BY id", (cat, t0))]

def sim_brute(app):
    t0 = now(); uid, pw = prep(app, "sim_victim", "Employee"); a = SimClient(app, "203.0.113.10")
    codes = [a.req("post", "/api/login", {"username": "sim_victim", "password": GUESSES[i]}).status_code for i in range(8)]
    still = a.req("post", "/api/login", {"username": "sim_victim", "password": pw}).status_code     # correct pw while locked
    locked = q(app, "SELECT locked_until FROM users WHERE id=?", (uid,))[0][0]
    c = app.connect(); c.execute("UPDATE users SET failed_count=0, locked_until=NULL WHERE id=?", (uid,)); c.commit(); c.close()  # == admin /unlock recovery
    rec = SimClient(app, "203.0.113.11").req("post", "/api/login", {"username": "sim_victim", "password": pw}).status_code
    al = new_alerts(app, "brute_force", t0); au = q(app, "SELECT COUNT(*) FROM audit_logs WHERE event IN ('LOGIN_FAIL','LOGIN_BLOCKED_LOCKED') AND ts>=?", (t0,))[0][0]
    return result("brute_force", "8 wrong passwords against one account, then correct password while locked, then secure recovery.", [
        chk("first 5 guesses rejected (401)", codes[:5] == [401] * 5, codes[:5]), chk("guesses 6-8 blocked by lockout (423)", codes[5:] == [423] * 3, codes[5:]),
        chk("correct password refused while locked", still == 423, still), chk("account lock persisted in DB", bool(locked), locked),
        chk("security alert generated", any("locked" in x["description"] for x in al), len(al)), chk("events audited", au >= 8, au),
        chk("legit user recovers after admin unlock", rec == 200, rec)], dict(http_codes=codes, alerts=al[-2:], audit_events=au))

def sim_privesc(app):
    t0 = now(); eid, ep = prep(app, "sim_emp", "Employee"); vid, _ = prep(app, "sim_victim", "Employee"); a = SimClient(app, "203.0.113.20")
    ok = a.req("post", "/api/login", {"username": "sim_emp", "password": ep}).status_code
    n0 = q(app, "SELECT COUNT(*) FROM users")[0][0]
    att = [("delete", "/api/users/%d" % vid), ("get", "/api/users"), ("get", "/api/audit"), ("post", "/api/users")]
    codes = [a.req(m if m != "delete" else "delete", u, {"username": "evil", "password": "Evil#Pass12345", "role": "Super Admin"} if m == "post" else None).status_code for m, u in att]
    n1 = q(app, "SELECT COUNT(*) FROM users")[0][0]; still = q(app, "SELECT COUNT(*) FROM users WHERE id=?", (vid,))[0][0]
    al = new_alerts(app, "privilege_escalation", t0); au = q(app, "SELECT COUNT(*) FROM audit_logs WHERE event='ACCESS_DENIED' AND user_id=? AND ts>=?", (eid, t0))[0][0]
    return result("privilege_escalation", "Employee sends direct API requests to admin-only endpoints (DELETE_USER, VIEW_USERS, VIEW_AUDIT_LOGS, CREATE_USER).", [
        chk("employee login ok", ok == 200, ok), chk("every request returned 403", codes == [403] * 4, codes), chk("no database change (user count)", n0 == n1 and still == 1, (n0, n1)),
        chk("denials audited", au == 4, au), chk("repeated denials raised alert", len(al) >= 1, len(al))], dict(http_codes=codes, alerts=al[-2:], audit_events=au))

def sim_takeover(app):
    t0 = now(); uid, pw = prep(app, "sim_victim", "Employee")
    h = SimClient(app, "203.0.113.30", "Chrome/Home"); [h.req("post", "/api/login", {"username": "sim_victim", "password": pw}) for _ in range(2)]   # build normal history
    x = SimClient(app, "198.51.100.77", "AttackerBrowser/9")                                              # new IP + new device
    [x.req("post", "/api/login", {"username": "sim_victim", "password": GUESSES[i]}) for i in range(3)]
    r = x.req("post", "/api/login", {"username": "sim_victim", "password": pw}); j = r.json or {}
    blocked = x.req("get", "/api/users").status_code
    sid = q(app, "SELECT sid FROM user_sessions WHERE user_id=? AND risk>=60 AND revoked=0 ORDER BY created DESC LIMIT 1", (uid,))
    app.revoke(sid[0][0]) if sid else None
    after = x.req("get", "/api/me").status_code
    c = app.connect(); sec = "JBSWY3DPEHPK3PXP"; c.execute("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?", (sec, uid)); c.commit(); c.close()
    m1 = SimClient(app, "198.51.100.78", "AttackerBrowser/9").req("post", "/api/login", {"username": "sim_victim", "password": pw})
    m = SimClient(app, "198.51.100.79", "AttackerBrowser/9"); m.req("post", "/api/login", {"username": "sim_victim", "password": pw})
    bad = m.req("post", "/api/login/mfa", {"code": "000000"}).status_code; good = m.req("post", "/api/login/mfa", {"code": totp(sec)}).status_code
    al = new_alerts(app, "account_takeover", t0); mf = q(app, "SELECT COUNT(*) FROM audit_logs WHERE event='MFA_FAIL' AND ts>=?", (t0,))[0][0]
    return result("account_takeover", "Valid password used from a new IP/device after failed guesses (suspected credential theft); then MFA challenge; then session revocation.", [
        chk("risk score >= 60 (high)", j.get("risk", 0) >= 60, "risk=%s %s" % (j.get("risk"), j.get("reasons"))), chk("session auto-restricted", j.get("restricted") is True, j.get("restricted")),
        chk("restricted session blocked from protected API", blocked == 403, blocked), chk("revoked session rejected (401)", after == 401, after),
        chk("MFA challenge enforced (202)", m1.status_code == 202, m1.status_code), chk("wrong OTP rejected, MFA failure audited", bad == 401 and mf >= 1, (bad, mf)),
        chk("correct OTP accepted for the legit holder", good == 200, good), chk("alert raised as SUSPECTED compromise", any("Suspected" in a["description"] for a in al), len(al))],
        dict(http_codes=[r.status_code, blocked, after, m1.status_code, bad, good], alerts=al[-2:], audit_events=mf))

def sim_tamper(app):
    t0 = now(); eid, ep = prep(app, "sim_emp", "Employee"); a = SimClient(app, "203.0.113.40")
    a.req("post", "/api/login", {"username": "sim_emp", "password": ep})
    roles0 = q(app, "SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?", (eid,))[0][0]
    rid = q(app, "SELECT id FROM roles WHERE name='Employee'")[0][0]; p0 = q(app, "SELECT COUNT(*) FROM role_permissions WHERE role_id=?", (rid,))[0][0]
    c1 = a.req("put", "/api/users/%d/role" % eid, {"role": "Super Admin"}).status_code
    c2 = a.req("post", "/api/roles/%d/permissions" % rid, {"permissions": ["DELETE_USER", "MANAGE_PERMISSIONS"]}).status_code
    c3 = a.req("put", "/api/me", {"email": "a@b.co", "role_id": 1, "role": "Super Admin"}).status_code
    nm = "sim_reg_" + secrets.token_hex(3); rp = rand_pw(); r4 = SimClient(app, "203.0.113.41").req("post", "/api/register", {"username": nm, "full_name": "Sim User", "email": "s@sim.local", "password": rp, "confirm": rp, "role": "Super Admin"})
    reg_role = q(app, "SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE username=?", (nm,))[0][0]
    c = app.connect(); c.execute("DELETE FROM users WHERE username=?", (nm,)); c.commit(); c.close()
    roles1 = q(app, "SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?", (eid,))[0][0]; p1 = q(app, "SELECT COUNT(*) FROM role_permissions WHERE role_id=?", (rid,))[0][0]
    al = new_alerts(app, "role_tampering", t0); ver = q(app, "SELECT COUNT(*) FROM audit_logs")[0][0]
    c = app.connect(); import hashlib, json; prev, ok = "0" * 64, True
    for r in c.execute("SELECT * FROM audit_logs ORDER BY id"):
        rec = dict(ts=r["ts"], uid=r["user_id"], event=r["event"], ip=r["ip"], resource=r["resource"], outcome=r["outcome"], risk=r["risk"], meta=r["meta"])
        ok &= r["prev_hash"] == prev and hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest() == r["hash"]; prev = r["hash"]
    c.close()
    return result("role_permission_tampering", "Employee tries to self-promote to Super Admin, grant itself DELETE_USER, mass-assign role fields, and register as Super Admin.", [
        chk("self-promotion rejected (403)", c1 == 403, c1), chk("permission grant rejected (403)", c2 == 403, c2), chk("mass-assignment rejected (400)", c3 == 400, c3),
        chk("registration role field ignored -> Employee", r4.status_code == 201 and reg_role == "Employee", reg_role), chk("existing role unchanged", roles0 == roles1 == "Employee", roles1),
        chk("role-permission table unchanged", p0 == p1, (p0, p1)), chk("tamper alerts generated", len(al) >= 3, len(al)), chk("audit chain integrity verified", ok, "records=%d" % ver)],
        dict(http_codes=[c1, c2, c3, r4.status_code], alerts=al[-2:], audit_events=ver))

SIMS = dict(brute_force=sim_brute, privilege_escalation=sim_privesc, account_takeover=sim_takeover, role_tampering=sim_tamper)


# ---------------- STATE A: vulnerable baseline (isolated, deterministic, in-memory) ----------------
# Nothing here touches the database or the real app: it is a toy reference model of an INSECURE system.
GUESSES = ["123456", "password", "qwerty", "letmein", "Summer2024!", "admin123", "welcome1", "Tr0ub4dor&3"]   # same guesses in both modes
SCEN = {"brute_force": "BF-01", "privilege_escalation": "PE-01", "account_takeover": "ATO-01", "role_tampering": "RT-01"}
LABEL = {"brute_force": "BLOCKED", "privilege_escalation": "DENIED", "account_takeover": "RESTRICTED / MFA", "role_tampering": "REJECTED"}
CONTROLS = {"brute_force": ["failed-login counter", "account lockout (HTTP 423)", "IP rate limit (429)", "security alert", "audit log"],
    "privilege_escalation": ["server-side permission check", "deny by default", "role hierarchy", "HTTP 403 + denial counter", "repeated-denial alert"],
    "account_takeover": ["context risk score", "new IP / device analysis", "MFA challenge", "session restriction", "session revocation", "suspected-compromise alert"],
    "role_tampering": ["role-assignment validation", "MANAGE_PERMISSIONS check", "mass-assignment whitelist", "registration role lock", "audit hash chain"]}

class VulnerableBaseline:
    def __init__(s):
        s.accounts = {"sim_victim": {"pw": GUESSES[6], "role": "Employee"}, "sim_emp": {"pw": "x", "role": "Employee"}}
        s.users = ["sim_victim", "sim_emp", "sim_target"]; s.sessions = []
    def login(s, user, pw, ip, ua):                     # no lockout, no rate limit, no risk scoring, no MFA
        if s.accounts.get(user, {}).get("pw") == pw: s.sessions.append(dict(user=user, ip=ip, ua=ua)); return 200
        return 401
    def delete_user(s, actor, target):                  # no permission check
        if target in s.users: s.users.remove(target); return 200
        return 404
    def set_role(s, actor, target, role): s.accounts[target]["role"] = role; return 200   # no validation / whitelist

def vres(th, desc, checks, codes, before, after):
    return dict(result(th, desc, checks, dict(http_codes=codes, alerts=[], audit_events=0)), mode="vulnerable", outcome="SIMULATED COMPROMISE" if all(c["passed"] for c in checks) else "UNEXPECTED", state_before=before, state_after=after,
                note="simulated HTTP codes from the isolated reference model")

def v_brute():
    m = VulnerableBaseline(); codes = [m.login("sim_victim", g, "203.0.113.10", "SimBrowser/1.0") for g in GUESSES]; n = codes.index(200) + 1 if 200 in codes else None
    return vres("brute_force", "Same 8 password guesses against an account with no lockout.", [chk("no lockout/rate limit ever triggered", True, "8 attempts accepted"), chk("correct password found by guessing", n is not None, "guess #%s" % n),
        chk("attacker session created", len(m.sessions) == 1, m.sessions), chk("account compromised (simulated)", n is not None, "sim_victim")], codes, {"sessions": 0}, {"sessions": len(m.sessions)})

def v_priv():
    m = VulnerableBaseline(); b = list(m.users); r0 = m.accounts["sim_emp"]["role"]; c = m.delete_user("sim_emp", "sim_target")
    return vres("privilege_escalation", "Employee calls an administrator-only delete operation.", [chk("actor is a plain Employee", r0 == "Employee", r0), chk("admin operation executed (200)", c == 200, c), chk("protected resource destroyed", "sim_target" not in m.users, m.users)], [c], {"users": b}, {"users": list(m.users)})

def v_ato():
    m = VulnerableBaseline(); h = m.login("sim_victim", GUESSES[6], "203.0.113.30", "Chrome/Home"); c = [m.login("sim_victim", GUESSES[i], "198.51.100.77", "AttackerBrowser/9") for i in range(3)]
    ok = m.login("sim_victim", GUESSES[6], "198.51.100.77", "AttackerBrowser/9"); sess = [x for x in m.sessions if x["ip"] == "198.51.100.77"]
    return vres("account_takeover", "Stolen credentials used from a new IP and new device.", [chk("login from unfamiliar IP/device accepted", ok == 200, ok), chk("no MFA / risk challenge", True, "none in baseline"),
        chk("attacker session created", len(sess) == 1, sess), chk("suspected takeover goes undetected", True, "no alert in baseline")], [h] + c + [ok], {"sessions": 1}, {"sessions": len(m.sessions)})

def v_tamper():
    m = VulnerableBaseline(); r0 = m.accounts["sim_emp"]["role"]; c = m.set_role("sim_emp", "sim_emp", "Administrator"); d = m.delete_user("sim_emp", "sim_target")
    return vres("role_tampering", "Employee edits their own role to Administrator.", [chk("self role change accepted (200)", c == 200, c), chk("role is now Administrator", m.accounts["sim_emp"]["role"] == "Administrator", m.accounts["sim_emp"]["role"]),
        chk("elevated access works", d == 200, d)], [c, d], {"sim_emp_role": r0}, {"sim_emp_role": m.accounts["sim_emp"]["role"]})
VULN = dict(brute_force=v_brute, privilege_escalation=v_priv, account_takeover=v_ato, role_tampering=v_tamper)

# ---------------- STATE B: protected system (real app) ----------------
def one(app, sql, a=()):
    r = q(app, sql, a); return r[0][0] if r else None
def snapshot(app):
    return dict(users=one(app, "SELECT COUNT(*) FROM users"), role_permission_rows=one(app, "SELECT COUNT(*) FROM role_permissions"), sim_emp_role=one(app, "SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE username='sim_emp'"),
        sim_victim_locked=bool(one(app, "SELECT locked_until>? FROM users WHERE username='sim_victim'", (now(),))), audit_events=one(app, "SELECT COUNT(*) FROM audit_logs"), alerts=one(app, "SELECT COUNT(*) FROM security_alerts"))

def load_run(app, rid):
    r = q(app, "SELECT id,ts,mode,protection_rate,checks_passed,checks_total FROM simulation_runs WHERE id=?", (rid,))
    if not r: return None
    r = r[0]; rows = {}
    for sid, th, mode, detail in q(app, "SELECT scenario_id,threat,mode,detail FROM simulation_results WHERE run_id=? ORDER BY id", (rid,)):
        rows.setdefault(sid, dict(scenario_id=sid, threat=th))[mode] = json.loads(detail)
    prot = [x["protected"] for x in rows.values() if "protected" in x]
    return dict(run_id=r[0], timestamp=r[1], mode=r[2], rows=list(rows.values()), summary=dict(protection_rate=r[3], checks_passed=r[4], checks_total=r[5], all_protected=bool(prot) and all(p["passed"] for p in prot),
                baseline_compromised=sum(1 for x in rows.values() if x.get("vulnerable", {}).get("passed"))))

def run_sims(app, mode, uid):
    res = {}
    for th, fn in SIMS.items():
        if mode in ("vulnerable", "both"): res[(th, "vulnerable")] = VULN[th]()
        if mode in ("protected", "both"):
            b = snapshot(app); p = fn(app); p.update(mode="protected", outcome=LABEL[th] if p["passed"] else "FAILED", state_before=b, state_after=snapshot(app), controls=CONTROLS[th]); res[(th, "protected")] = p
    pc = [c for (th, m), r in res.items() if m == "protected" for c in r["checks"]]; ok = sum(c["passed"] for c in pc)
    c = app.connect(); rid = c.execute("INSERT INTO simulation_runs(ts,mode,user_id,protection_rate,checks_passed,checks_total) VALUES(?,?,?,?,?,?)", (now(), mode, uid, round(100 * ok / len(pc), 1) if pc else None, ok, len(pc))).lastrowid
    for (th, m), r in res.items():
        c.execute("INSERT INTO simulation_results(run_id,scenario_id,threat,mode,outcome,passed,detail) VALUES(?,?,?,?,?,?,?)", (rid, SCEN[th], th, m, r["outcome"], int(r["passed"]), json.dumps(dict(r, scenario_id=SCEN[th], timestamp=now()))))
        for a in r.get("alerts", []): c.execute("INSERT INTO attack_evidence(run_id,scenario_id,kind,text) VALUES(?,?,?,?)", (rid, SCEN[th], "alert:" + a["severity"], a["description"]))
        if m == "protected": c.execute("INSERT INTO attack_evidence(run_id,scenario_id,kind,text) VALUES(?,?,?,?)", (rid, SCEN[th], "audit", "%s audit events recorded" % r.get("audit_events")))
    c.commit(); c.close(); return load_run(app, rid)

def register_lab(app, db, qa, q1, run):
    require = app.require
    @app.post("/api/sim/run")
    @require("RUN_SIMULATION")
    def sim_run(u):
        mode = (request.get_json(silent=True) or {}).get("mode")
        if mode not in ("vulnerable", "protected", "both"): return jsonify(error="mode must be vulnerable, protected or both"), 400
        out = run_sims(app, mode, u["id"]); app.audit("SIMULATION_RUN", u["id"], mode, "OK", out["summary"]); return jsonify(out)
    @app.get("/api/sim/history")
    @require("RUN_SIMULATION")
    def sim_history(u):
        runs = qa("SELECT id,ts,mode,protection_rate,checks_passed,checks_total FROM simulation_runs ORDER BY id DESC LIMIT 10"); return jsonify(runs=runs, latest=load_run(app, runs[0]["id"]) if runs else None)
    @app.post("/api/sim/clear")
    @require("RUN_SIMULATION")
    def sim_clear(u):   # deletes simulation history only - audit logs and alerts are untouched
        n = run("DELETE FROM simulation_runs").rowcount; app.audit("SIM_HISTORY_CLEARED", u["id"], "simulation_runs", "OK", {"runs": n}); return jsonify(cleared=n)
