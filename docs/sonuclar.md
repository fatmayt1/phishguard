# Model Sonuçları (24.11.2026)

## Veri
- Veritabanından çekilen satır: 11.430 (0.19 sn)
- Eksik değer: 0 | Tekrar eden URL: 1 (atıldı)
- Eğitim: 9.143 | Test: 2.286 (%80/%20, stratify)
- Kullanılan özellik: 18 (sadece URL'den hesaplananlar)

## Metrikler
| Metrik    | Logistic Regression | Random Forest |
|-----------|---------------------|---------------|
| Accuracy  | 0.8228              | 0.8876        |
| Precision | 0.8271              | 0.8852        |
| Recall    | 0.8163              | 0.8906        |
| F1        | 0.8217              | 0.8879        |

## Karışıklık matrisleri [[TN, FP], [FN, TP]]
- LR: [[948, 195], [210, 933]]
- RF: [[1011, 132], [125, 1018]]

## Yorumlar (rapor için)
- RF tüm metriklerde ~6 puan önde: özellikler arası birleşik
  (doğrusal olmayan) ilişkileri yakalayabiliyor.
- Precision ve recall dengeli: ne aşırı alarm ne aşırı kaçırma.
- Kaçırılan phishing (FN): LR 210 → RF 125 (~%40 azalma).
  Güvenlik açısından en kritik hata türü bu.
- 87 özelliğin tamamı değil, yalnızca URL'den hesaplanabilen
  18 özellik kullanıldı. Amaç: canlı demoda siteye bağlanmadan
  anında karar verebilmek. Bilinçli bir hız/güvenlik - başarı
  ödünleşimi.
- Seçilen model: Random Forest (ml/model.pkl)