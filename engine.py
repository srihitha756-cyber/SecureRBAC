"""Explainable ML layer (advisory only - never the sole allow/deny decision).
IsolationForest (unsupervised, trained on benign events only) + RandomForest (supervised, 4 threat classes).
Synthetic data; train/test sets use different seeds, models are fit on train only (no leakage)."""
import json, os
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix, accuracy_score

DIR = os.path.join(os.path.dirname(__file__), "models")
FEATS = ["fails_10m", "distinct_users_ip", "new_ip", "new_ua", "mfa_fails", "denied_403", "role_attempts", "odd_hour"]
CLASSES = ["benign", "brute_force", "privilege_escalation", "account_takeover", "role_tampering"]

def gen(n, kind, rng):
    P, B = rng.poisson, rng.binomial
    d = dict(fails_10m=P(0.4, n), distinct_users_ip=1 + P(0.1, n), new_ip=B(1, .08, n), new_ua=B(1, .08, n),
             mfa_fails=B(1, .03, n), denied_403=P(0.15, n), role_attempts=B(1, .01, n), odd_hour=B(1, .1, n))
    if kind == "brute_force":
        d["fails_10m"] = rng.integers(5, 30, n); d["distinct_users_ip"] = rng.integers(1, 7, n)
    elif kind == "privilege_escalation":
        d["denied_403"] = rng.integers(3, 16, n); d["role_attempts"] = P(0.5, n)
    elif kind == "account_takeover":
        d["fails_10m"] = rng.integers(2, 7, n); d["new_ip"] = np.ones(n, int); d["new_ua"] = B(1, .8, n)
        d["mfa_fails"] = rng.integers(0, 4, n); d["odd_hour"] = B(1, .6, n)
    elif kind == "role_tampering":
        d["role_attempts"] = rng.integers(2, 9, n); d["denied_403"] = rng.integers(2, 9, n)
    df = pd.DataFrame(d)[FEATS]; df["label"] = kind
    return df

def dataset(seed, nb, na):
    rng = np.random.default_rng(seed)
    return pd.concat([gen(nb, "benign", rng)] + [gen(na, k, rng) for k in CLASSES[1:]], ignore_index=True)

def rule_based(r):  # deterministic rules, same logic family as the backend
    return int(r.fails_10m >= 5 or r.denied_403 >= 3 or r.role_attempts >= 2 or
               (r.new_ip and r.new_ua and (r.fails_10m >= 2 or r.mfa_fails >= 1)))

def train():
    tr, te = dataset(1, 3000, 600), dataset(2, 1500, 300)
    iso = IsolationForest(n_estimators=200, contamination=0.03, random_state=0).fit(tr[tr.label == "benign"][FEATS])
    rf = RandomForestClassifier(n_estimators=200, random_state=0).fit(tr[FEATS], tr.label)
    y = (te.label != "benign").astype(int)
    out = {"train_rows": len(tr), "test_rows": len(te), "features": FEATS}
    def m(pred, name):
        p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        out[name] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
                     "accuracy": round(accuracy_score(y, pred), 4), "confusion_matrix_TN_FP_FN_TP": confusion_matrix(y, pred).ravel().tolist()}
        tn, fp, fn, tp = confusion_matrix(y, pred).ravel(); out[name]["false_positive_rate"] = round(fp / (fp + tn), 4); out[name]["false_negative_rate"] = round(fn / (fn + tp), 4)
    m((iso.predict(te[FEATS]) == -1).astype(int), "isolation_forest")
    m(te.apply(rule_based, axis=1).values, "rule_based")
    pred = rf.predict(te[FEATS])
    out["random_forest_multiclass"] = {"accuracy": round(accuracy_score(te.label, pred), 4),
        "per_class_recall": {c: round(float((pred[(te.label == c).values] == c).mean()), 4) for c in CLASSES},
        "per_class_precision_recall_f1": {c: {k: round(v, 4) for k, v in r.items() if k != "support"} for c, r in classification_report(te.label, pred, output_dict=True, zero_division=0).items() if c in CLASSES}, "labels": CLASSES, "confusion_matrix": confusion_matrix(te.label, pred, labels=CLASSES).tolist()}
    out["evaluation_type"] = "SYNTHETIC data only - not real labeled attack traffic"; out["limitations"] = "Synthetic data: real-world accuracy will be lower; false positives expected for travellers/new devices. Advisory only."
    os.makedirs(DIR, exist_ok=True)
    joblib.dump({"iso": iso, "rf": rf}, os.path.join(DIR, "model.joblib"))
    json.dump(out, open(os.path.join(DIR, "metrics.json"), "w"), indent=2)
    return out

_cache = {}
def predict(feat):
    p = os.path.join(DIR, "model.joblib")
    if not os.path.exists(p): return None
    if "m" not in _cache: _cache["m"] = joblib.load(p)
    X = pd.DataFrame([{k: feat.get(k, 0) for k in FEATS}]); m = _cache["m"]
    return {"anomaly": bool(m["iso"].predict(X)[0] == -1), "score": round(float(-m["iso"].score_samples(X)[0]), 3),
            "predicted_class": str(m["rf"].predict(X)[0])}

def metrics():
    p = os.path.join(DIR, "metrics.json")
    return json.load(open(p)) if os.path.exists(p) else None
