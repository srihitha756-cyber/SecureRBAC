[README.md](https://github.com/user-attachments/files/34808023/README.md)
# SecureRBAC - Adaptive Role-Based Access Management (4-threat demo)
Flask + SQLite + Bootstrap 5 + Chart.js + scikit-learn + ReportLab.

## Run (Windows CMD, in VS Code terminal)
```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python run.py
```
Open http://127.0.0.1:5000  (or double-click `run.bat`). First start creates/migrates `instance\rbac.db` (old DBs are backed up first), seeds users only if missing, and trains the ML model.
Tests: `python -m pytest -v`

## Demo login (local classroom demo ONLY)
`admin` / `admin@12345` (Administrator). Override with env var `DEMO_ADMIN_PASSWORD` before first start; use a strong secret for any real deployment. The seed never overwrites an existing password. Other seeded accounts (superadmin, analyst1, manager1, employee1) get random passwords printed once at first start. Public registration always creates an Employee.

## Professor demo
1. Sign in as admin -> **Attack Simulation Lab** -> **Run Both & Compare**.
2. State A (vulnerable baseline) = isolated in-memory model; all 4 attacks "SIMULATED COMPROMISE". State B = same scenario IDs/inputs replayed against the real app: BLOCKED / DENIED / RESTRICTED-MFA / REJECTED, shown only if the checks confirm them. Protection rate = passed protected checks / total protected checks (measured; any failure shows FAILED).
3. Show **Security Monitoring** (4 threat panels, alerts, ML metrics), **Audit Logs** (hash chain), **Policy Verification**, then **Reports** (PDF/CSV).
Scenarios: BF-01 brute force (8 guesses), PE-01 employee admin delete, ATO-01 stolen credentials from new IP/device, RT-01 employee self-promotion + mass assignment.

## Honest limitations
- ML is trained on SYNTHETIC data only; its metrics are not real-world accuracy and it is advisory (never decides access).
- Hash-chained audit logs detect tampering by application users, not a DB/OS administrator who rewrites the whole chain.
- IP/device changes indicate *suspected* compromise only. Pre-auth endpoints (login/register) are exempt from the CSRF token (no session exists yet); all authenticated state-changing calls require it.
- Not implemented: QR image for MFA (secret shown), recovery codes, password-reset email, temporary role expiry, role-creation UI. Uses stdlib sqlite3 + built-in RFC-6238 TOTP + own rate limiting (no Flask-SQLAlchemy/PyOTP/Flask-Limiter). Test coverage % not measured. UI not verified in a real browser by me.
