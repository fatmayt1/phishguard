# features.py'nin hesapladığı değerleri, veritabanındaki orijinal değerlerle karşılaştırır.

import sys
import numpy as np
import pandas as pd
from sqlalchemy import create_engine

sys.path.append("app")
from features import extract_features

DB_URL = "postgresql+psycopg2://fatma:fatma123@localhost:5432/phishguard"
engine = create_engine(DB_URL)

df = pd.read_sql("SELECT * FROM urls;", engine)
ours = pd.DataFrame([extract_features(u) for u in df["url"]])

print(f"{'Özellik':<20} Eşleşme oranı")
print("-" * 36)
for col in ours.columns:
    match = np.isclose(ours[col], df[col], atol=1e-3).mean()
    flag = "" if match > 0.95 else "   <-- dikkat"
    print(f"{col:<20} %{match * 100:5.1f}{flag}")