import pandas as pd
import joblib

# Load model and data
model = joblib.load("baseline_model.pkl")
data = pd.read_csv("traffic_data.csv")

# Features used by the model
feature_cols = ["duration", "packets", "bytes", "rate"]
features = data[feature_cols]

# Baseline statistics (normal behavior)
baseline_mean = features.mean()
baseline_std = features.std()

# Predict anomalies
data["anomaly"] = model.predict(features)

# Select only anomalies
anomalies = data[data["anomaly"] == -1]

def explain_row(row):
    explanations = []
    for col in feature_cols:
        deviation = (row[col] - baseline_mean[col]) / baseline_std[col]
        if abs(deviation) > 2:  # significant deviation
            explanations.append(
                f"{col} deviates by {deviation:.2f} standard deviations"
            )
    return explanations

print("\nExplainability Report:\n")

for idx, row in anomalies.head(5).iterrows():
    print(f"Traffic Record {idx}:")
    reasons = explain_row(row)
    for r in reasons:
        print(" -", r)
    print()
