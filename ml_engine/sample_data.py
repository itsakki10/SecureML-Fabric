import pandas as pd
import numpy as np

 
np.random.seed(42)
normal_data = pd.DataFrame({
    "duration": np.random.normal(10, 2, 500),
    "packets": np.random.normal(200, 50, 500),
    "bytes": np.random.normal(15000, 3000, 500),
    "rate": np.random.normal(20, 5, 500)
})


anomaly_data = pd.DataFrame({
    "duration": np.random.normal(2, 0.5, 50),
    "packets": np.random.normal(1000, 200, 50),
    "bytes": np.random.normal(80000, 10000, 50),
    "rate": np.random.normal(300, 50, 50)
})

data = pd.concat([normal_data, anomaly_data])
data.to_csv("traffic_data.csv", index=False)
print("Sample traffic data generated")
