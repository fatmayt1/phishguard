# URL'den, modelin eğitildiği 18 özelliği hesaplar.
# Tanımlar veri setinin (Hannousse & Yahiouche, 2021) özellik tanımlarıyla
# uyumlu olacak şekilde yazıldı; tutarlılık scripts/check_features.py ile test edildi.

import re
from urllib.parse import urlparse

# Path içinde aranan şüpheli kelimeler (phish_hints)
HINTS = ["wp", "login", "includes", "admin", "content", "site", "images", "js",
         "alibaba", "css", "myaccount", "dropbox", "themes", "plugins",
         "signin", "view"]

# Dolandırıcılıkta sık kullanılan alan adı uzantıları
SUSPICIOUS_TLDS = {"fit", "tk", "gp", "ga", "work", "ml", "date", "wang", "men",
                   "icu", "online", "click", "country", "stream", "download",
                   "xin", "racing", "jetzt", "ren", "mom", "party", "review",
                   "trade", "accountants", "science", "ninja", "xyz", "faith",
                   "zip", "cricket", "win", "accountant", "realtor", "top",
                   "christmas", "gdn", "link", "asia", "club", "la", "ae",
                   "exposed", "pe", "rs", "audio", "website", "bj", "mx", "media"}

# Veri setindeki tanımla aynı: IPv4, hex IPv4, IPv6 veya art arda 7 hex karakter
IP_PATTERN = re.compile(
    r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\."
    r"([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|"
    r"((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\."
    r"(0x[0-9a-fA-F]{1,2})\/)|"
    r"(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|"
    r"[0-9a-fA-F]{7}"
)

# Veri setindeki tanımla aynı: linkin herhangi bir yerinde aranan kısaltma servisleri
SHORTENER_PATTERN = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|"
    r"snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|"
    r"om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|"
    r"tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|"
    r"cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|"
    r"vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)

# Veri setindeki tanımla aynı: ilk tireden sonra '/' geliyor mu
PREFIX_SUFFIX_PATTERN = re.compile(r"https?://[^\-]+-[^\-]+/")


def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in host)

    return {
        "length_url": len(url),
        "length_hostname": len(host),
        "ip": 1 if IP_PATTERN.search(url) else 0,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_slash": url.count("/"),
        "nb_www": url.lower().count("www"),
        "ratio_digits_url": digits_url / len(url) if url else 0,
        "ratio_digits_host": digits_host / len(host) if host else 0,
        "prefix_suffix": 1 if PREFIX_SUFFIX_PATTERN.search(url) else 0,
        "shortening_service": 1 if SHORTENER_PATTERN.search(url) else 0,
        "phish_hints": sum(path.lower().count(h) for h in HINTS),
        "suspecious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
    }


if __name__ == "__main__":
    # Hızlı deneme
    print(extract_features("http://www.crestonwood.com/router.php"))