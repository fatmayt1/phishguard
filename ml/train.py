# PhishGuard - Model eğitimi
# Veriyi PostgreSQL'den çeker, iki modeli eğitip karşılaştırır,
# metrikleri ve test tahminlerini tekrar veritabanına yazar.

import time
import joblib
import pandas as pd
from sqlalchemy import create_engine, text
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

DB_URL = "postgresql+psycopg2://fatma:fatma123@localhost:5432/phishguard"

FEATURES = [
    "length_url", "length_hostname", "ip",
    "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_eq",
    "nb_underscore", "nb_slash", "nb_www",
    "ratio_digits_url", "ratio_digits_host",
    "prefix_suffix", "shortening_service", "phish_hints", "suspecious_tld",
]


# ---------- 1) VERİYİ VERİTABANINDAN ÇEK ----------
def load_data(engine):
    query = f"SELECT id, url, {', '.join(FEATURES)}, status FROM urls;"
    start = time.time()
    df = pd.read_sql(query, engine)
    print(f"[1] Veritabanından {len(df)} satır çekildi "
          f"({time.time() - start:.2f} sn)")
    return df


# ---------- 2) ÖN İŞLEME ----------
def preprocess(df):
    # Eksik değer kontrolü
    missing = df[FEATURES].isna().sum().sum()
    print(f"[2] Eksik değer sayısı: {missing}")
    df = df.dropna(subset=FEATURES)

    # Aynı URL birden fazla varsa tekrarları at
    before = len(df)
    df = df.drop_duplicates(subset="url").copy()
    print(f"[2] Tekrar eden URL sayısı: {before - len(df)}")

    # Etiketi sayıya çevir: phishing = 1, legitimate = 0
    df["label"] = (df["status"] == "phishing").astype(int)
    return df



# ---------- 3) MODELLER ----------
# ---------- 3) MODELLER ----------
def get_models():
    return {
        # LR, özelliklerin aynı ölçekte olmasından etkilenir -> StandardScaler
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000)),
        ]),
        # kNN mesafe hesapladığı için ölçeğe çok duyarlı -> StandardScaler
        "KNN": Pipeline([
            ("scaler", StandardScaler()),
            ("model", KNeighborsClassifier(n_neighbors=5)),
        ]),
        # Ağaç tabanlı modeller ölçekten etkilenmez, ölçeklemeye gerek yok
        "RandomForest": RandomForestClassifier(
            n_estimators=200, random_state=42, n_jobs=-1
        ),
        "GradientBoosting": GradientBoostingClassifier(random_state=42),
    }


# ---------- 4) DEĞERLENDİRME ----------
def evaluate(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
    }


# ---------- 5) SONUÇLARI VERİTABANINA YAZ ----------
def save_run(engine, name, m, train_size, test_size):
    with engine.begin() as conn:
        run_id = conn.execute(text("""
            INSERT INTO model_runs (model_name, accuracy, precision_score,
                                    recall_score, f1_score, train_size, test_size)
            VALUES (:name, :acc, :prec, :rec, :f1, :tr, :te)
            RETURNING id;
        """), {"name": name, "acc": m["accuracy"], "prec": m["precision"],
               "rec": m["recall"], "f1": m["f1"],
               "tr": train_size, "te": test_size}).scalar()
    return run_id


def save_predictions(engine, test_df, y_pred, y_proba, run_id):
    out = pd.DataFrame({
        "url": test_df["url"].values,
        "url_id": test_df["id"].values,
        "model_run_id": run_id,
        "predicted_label": ["phishing" if p == 1 else "legitimate" for p in y_pred],
        "probability": y_proba,
        "source": "test",
    })
    out.to_sql("predictions", engine, if_exists="append", index=False)
    print(f"[5] {len(out)} test tahmini predictions tablosuna yazıldı")

    

def main():
    engine = create_engine(DB_URL)

    df = preprocess(load_data(engine))

    # %80 eğitim, %20 test. stratify: iki sette de phishing oranı aynı kalsın
    train_df, test_df = train_test_split(
        df, test_size=0.2, stratify=df["label"], random_state=42
    )
    X_train, y_train = train_df[FEATURES], train_df["label"]
    X_test, y_test = test_df[FEATURES], test_df["label"]
    print(f"[3] Eğitim: {len(train_df)}  Test: {len(test_df)}")

    best = None
    for name, model in get_models().items():
        model.fit(X_train, y_train)                    # eğit
        y_pred = model.predict(X_test)                 # tahmin et (0/1)
        y_proba = model.predict_proba(X_test)[:, 1]    # phishing olasılığı

        m = evaluate(y_test, y_pred)
        run_id = save_run(engine, name, m, len(train_df), len(test_df))

        print(f"\n[4] {name} (run_id={run_id})")
        for k, v in m.items():
            print(f"    {k:<10}: {v:.4f}")
        print("    Karışıklık matrisi [[TN, FP], [FN, TP]]:")
        print(f"    {confusion_matrix(y_test, y_pred).tolist()}")

        # F1'i en yüksek olan modeli sakla
        if best is None or m["f1"] > best["f1"]:
            best = {"name": name, "model": model, "f1": m["f1"],
                    "run_id": run_id, "y_pred": y_pred, "y_proba": y_proba}

    print(f"\n[5] En iyi model: {best['name']} (F1 = {best['f1']:.4f})")
    save_predictions(engine, test_df, best["y_pred"], best["y_proba"], best["run_id"])

    # En iyi modeli dosyaya kaydet (Flask API bunu kullanacak)
    joblib.dump({"model": best["model"], "features": FEATURES,
                 "run_id": best["run_id"]}, "ml/model.pkl")
    print("[5] Model ml/model.pkl dosyasına kaydedildi")


if __name__ == "__main__":
    main()