-- PhishGuard veritabanı şeması

-- 1) Eğitim verisi: URL ler ve seçilen 18 özellik
CREATE TABLE urls (
    id                  SERIAL PRIMARY KEY,
    url                 TEXT NOT NULL,
    length_url          INT,
    length_hostname     INT,
    ip                  SMALLINT,
    nb_dots             INT,
    nb_hyphens          INT,
    nb_at               INT,
    nb_qm               INT,
    nb_and              INT,
    nb_eq               INT,
    nb_underscore       INT,
    nb_slash            INT,
    nb_www              INT,
    ratio_digits_url    REAL,
    ratio_digits_host   REAL,
    prefix_suffix       SMALLINT,
    shortening_service  SMALLINT,
    phish_hints         INT,
    suspecious_tld      SMALLINT,
    status              VARCHAR(10) NOT NULL
                        CHECK (status IN ('legitimate', 'phishing')),
    created_at          TIMESTAMP DEFAULT NOW()
);

-- 2)Her model eğitiminin performans metrikleri
CREATE TABLE model_runs (
    id               SERIAL PRIMARY KEY,
    model_name       VARCHAR(50) NOT NULL,
    accuracy         REAL,
    precision_score  REAL,
    recall_score     REAL,
    f1_score         REAL,
    train_size       INT,
    test_size        INT,
    trained_at       TIMESTAMP DEFAULT NOW()
);

-- 3) Model tahminleri (sonuçların tekrar DB'ye yazılması)
CREATE TABLE predictions (
    id               SERIAL PRIMARY KEY,
    url              TEXT NOT NULL,
    url_id           INT REFERENCES urls(id),
    model_run_id     INT REFERENCES model_runs(id),
    predicted_label  VARCHAR(10) NOT NULL,
    probability      REAL,
    source           VARCHAR(10) CHECK (source IN ('test', 'live')),
    created_at       TIMESTAMP DEFAULT NOW()
);

-- İndeksler = sık sorgulanan sütunları hızlandırır
CREATE INDEX idx_urls_status ON urls(status);
CREATE INDEX idx_predictions_created ON predictions(created_at DESC);
