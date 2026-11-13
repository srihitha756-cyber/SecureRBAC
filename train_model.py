import json
from ml.engine import train
o = train()
print(json.dumps({k: o[k] for k in ("isolation_forest", "rule_based")}, indent=1)); print("RandomForest 4-threat accuracy:", o["random_forest_multiclass"]["accuracy"])
