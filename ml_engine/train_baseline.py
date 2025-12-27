import pandas as pd
from sklearn.ensemble import IsolationForest

data = pd.read_csv("traffic_data.csv")

model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)

model.fit(data)

import joblib
joblib.dump(model, "baseline_model.pkl")
print("Baseline model trained")
