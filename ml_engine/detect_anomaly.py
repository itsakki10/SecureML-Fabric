import pandas as pd
import joblib

# Load trained model
model = joblib.load("baseline_model.pkl")

# Load traffic data
data = pd.read_csv("live_traffic.csv")

# Use ONLY the features used during training
features = data[["duration", "packets", "bytes", "rate"]]

# Get anomaly scores
data["anomaly_score"] = model.decision_function(features)

# Predict anomalies
data["anomaly"] = model.predict(features)

# -1 = anomaly, 1 = normal
alerts = data[data["anomaly"] == -1]

print("Anomalies detected:")
print(alerts.head())
