# PhishGuard - Flask API
# Kullanıcının gönderdiği URL'yi sınıflandırır, sonucu veritabanına kaydeder.

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flasgger import Swagger
from sqlalchemy import create_engine, text

from features import extract_features

# ---------- AYARLAR ----------
# Ortam değişkeni varsa onu, yoksa varsayılanı kullan (Docker'da işe yarayacak)
DB_URL = os.getenv(
    "DB_URL", "postgresql+psycopg2://fatma:fatma123@localhost:5432/phishguard"
)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "..", "ml", "model.pkl"))

# ---------- BAŞLANGIÇ: model ve veritabanı ----------
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
FEATURES = bundle["features"]
MODEL_RUN_ID = bundle["run_id"]

engine = create_engine(DB_URL)

app = Flask(__name__)
app.config["SWAGGER"] = {
    "title": "PhishGuard API",
    "uiversion": 3,
    "version": "1.0.0",
    # Swagger sayfasına kendi temamızı ekle
    "head_text": '<link rel="stylesheet" href="/static/swagger-theme.css">',
}
Swagger(app)


# ---------- 1) TAHMİN ----------
@app.route("/predict", methods=["POST"])
def predict():
    """
    Bir URL için phishing tahmini yapar ve sonucu veritabanına kaydeder.
    ---
    tags:
      - Tahmin
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [url]
          properties:
            url:
              type: string
              example: http://paypal.com.secure-login.verify-account.xyz/signin
    responses:
      200:
        description: Tahmin sonucu
      400:
        description: Geçersiz istek
    """
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "url alanı zorunlu"}), 400
    # Veri setindeki tüm URL'ler http/https ile başlıyor, aynı formata getir
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    feats = extract_features(url)
    X = pd.DataFrame([feats])[FEATURES]
    proba = float(model.predict_proba(X)[0][1])          # phishing olasılığı
    label = "phishing" if proba >= 0.5 else "legitimate"

    # Sonucu veritabanına yaz
    with engine.begin() as conn:
        row = conn.execute(text("""
            INSERT INTO predictions (url, model_run_id, predicted_label,
                                     probability, source)
            VALUES (:url, :run_id, :label, :proba, 'live')
            RETURNING id, created_at;
        """), {"url": url, "run_id": MODEL_RUN_ID,
               "label": label, "proba": proba}).mappings().one()

    return jsonify({
        "id": row["id"],
        "url": url,
        "prediction": label,
        "probability": round(proba, 4),
        "features": feats,
        "created_at": row["created_at"].isoformat(),
    })


# ---------- 2) SON TAHMİNLER ----------
@app.route("/predictions", methods=["GET"])
def predictions():
    """
    Veritabanındaki son tahminleri listeler.
    ---
    tags:
      - Tahmin
    parameters:
      - in: query
        name: limit
        type: integer
        default: 20
      - in: query
        name: source
        type: string
        enum: [live, test]
        required: false
    responses:
      200:
        description: Tahmin listesi
    """
    limit = min(request.args.get("limit", 20, type=int), 200)
    source = request.args.get("source")

    query = """SELECT id, url, predicted_label, probability, source, created_at
               FROM predictions"""
    params = {"limit": limit}
    if source in ("live", "test"):
        query += " WHERE source = :source"
        params["source"] = source
    query += " ORDER BY id DESC LIMIT :limit;"

    with engine.connect() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return jsonify([
        {**dict(r), "probability": round(r["probability"], 4),
         "created_at": r["created_at"].isoformat()}
        for r in rows
    ])


# ---------- 3) MODEL METRİKLERİ ----------
@app.route("/metrics", methods=["GET"])
def metrics():
    """
    Eğitilen modellerin performans metriklerini döndürür.
    ---
    tags:
      - Model
    responses:
      200:
        description: Model metrikleri
    """
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, model_name, accuracy, precision_score, recall_score,
                   f1_score, train_size, test_size, trained_at
            FROM model_runs ORDER BY id;
        """)).mappings().all()

    return jsonify({
        "active_model_run_id": MODEL_RUN_ID,
        "runs": [{**dict(r), "trained_at": r["trained_at"].isoformat()}
                 for r in rows],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

    