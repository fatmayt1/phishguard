# CSV'deki URL verisini PostgreSQL'deki urls tablosuna bir kez aktarır.

import pandas as pd
from sqlalchemy import create_engine

# Veritabanı bağlantı adresi: kullanici:sifre@sunucu:port/veritabani
DB_URL = "postgresql+psycopg2://fatma:fatma123@localhost:5432/phishguard"

# Modelde kullanacağımız 18 özellik + url + etiket
COLUMNS = [
    "url",
    "length_url", "length_hostname", "ip",
    "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_eq",
    "nb_underscore", "nb_slash", "nb_www",
    "ratio_digits_url", "ratio_digits_host",
    "prefix_suffix", "shortening_service", "phish_hints", "suspecious_tld",
    "status",
]

def main():
    # 1) CSV'yi oku, sadece ihtiyacımız olan sütunları al
    df = pd.read_csv("data/dataset_phishing.csv", usecols=COLUMNS)
    print(f"CSV okundu: {len(df)} satır, {len(df.columns)} sütun")

    # 2) Veritabanına bağlan
    engine = create_engine(DB_URL)

    # 3) urls tablosuna ekle (tablo init.sql ile zaten oluşturuldu)
    df.to_sql("urls", engine, if_exists="append", index=False)
    print("Veri urls tablosuna yüklendi.")

if __name__ == "__main__":
    main()