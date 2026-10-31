# Writeup — Pantai Marina

| Info | Detail |
|---|---|
| Kategori | OSINT |
| Poin | 245 (awal 300, min 150) |
| Solve | 11 |
| First blood | Raksa |
| Flag | `CF2{osint_pantai_marina_1e6a2bc634e8564f0b4f4549}` |

## Deskripsi Soal

> Dimas (@dimas_senja) mengaku naik kapal terakhir yang benar-benar berlayar dari Marina pada 12 Oktober 2026. Laporan ditutup pukul 18.00 WIB. Tentukan perjalanan dan tiket yang berlaku saat laporan ditutup.
>
> Jawaban: susun `TRIP|TICKET|STATE` dari bukti. Gunakan huruf besar/kecil persis seperti sumber, tanpa spasi tambahan, UTF-8, tanpa newline. Kirim `CF2{osint_pantai_marina_<24 karakter pertama SHA256(teks tersebut), heksadesimal huruf kecil>}`.

Lampiran: `osint-pantai-marina-lampiran.zip`

## Isi Lampiran

```
manifest-versions.csv   -> riwayat versi manifes penumpang (trip, passenger, ticket, version_at, state)
post.txt                -> unggahan @dimas_senja
rules.txt               -> aturan interpretasi data
trip-status.csv         -> status tiap perjalanan (trip, date_WIB, departure_WIB, status, updated_at)
```

### post.txt

```
@dimas_senja: pulang dengan kapal terakhir yang jadi berlayar, 12 Oktober 2026. Receipt akun pelanggan PX-883.
```

Dari sini kita tahu ID penumpang Dimas adalah **PX-883**.

### rules.txt

```
Status SAILED berarti benar-benar berlayar; SCHEDULED belum menjadi bukti berlayar.
Manifes append-only: untuk tiap trip+passenger, gunakan versi terakhir pada/before waktu penutupan laporan.
State booked belum membuktikan boarded. Semua waktu berzona WIB.
```

Ada tiga aturan penting di sini:

1. Hanya status `SAILED` yang membuktikan kapal berlayar.
2. Manifes bersifat *append-only*. Untuk tiap pasangan trip+penumpang, pakai versi **terakhir yang `version_at` ≤ 18:00 WIB**.
3. `booked` belum berarti `boarded`.

## Analisis

### Langkah 1 — Cari kapal terakhir yang berlayar pada 12 Oktober 2026

Semua kapal reguler (TR-1xx) pada 12 Oktober berangkat paling lambat pukul **16:00**. Kandidat yang lebih sore adalah tiga kapal TR-70x:

| Trip | Berangkat | Status | updated_at | Keterangan |
|---|---|---|---|---|
| TR-703 | 17:45 | `SCHEDULED` | 17:00 | Belum terbukti berlayar, jadi gugur |
| TR-701 | 17:30 | `CANCELLED` | 17:10 | Dibatalkan, jadi gugur |
| **TR-702** | **17:15** | **`SAILED`** | **17:20** | Berlayar, dan status diperbarui sebelum 18:00 |

Jebakannya, kapal yang jadwalnya paling sore (TR-703) belum tentu berangkat. Kapal terakhir yang benar-benar berlayar adalah **TR-702**.

### Langkah 2 — Cari tiket PX-883 yang berlaku di TR-702 saat laporan ditutup

Baris manifes untuk `TR-702` + `PX-883`:

| trip | passenger | ticket | version_at | state |
|---|---|---|---|---|
| TR-702 | PX-883 | 0915 | 2026-10-12T16:00:00+07:00 | booked |
| TR-702 | PX-883 | **0926** | **2026-10-12T17:18:00+07:00** | **boarded** |

Kedua versi dibuat sebelum 18:00. Versi terakhirnya adalah pukul **17:18**, yaitu tiket **`0926`** dengan state **`boarded`**.

Perhatikan bahwa tiket ditulis `0926` dengan angka nol di depan. Nilai ini harus diperlakukan sebagai string, jangan diubah menjadi integer.

### Pengecoh yang perlu dihindari

- **TR-701 / tiket `0880` (booked):** kapalnya `CANCELLED` dan state-nya hanya `booked`.
- **TR-702 / tiket `0915` (booked):** versi lama yang sudah digantikan oleh versi 17:18.
- **Puluhan baris PX-883 `boarded` di kapal TR-1xx:** semuanya tercatat pada 12 Oktober pukul 16:00–17:57, padahal banyak kapalnya berangkat 11 Oktober atau lebih awal. Yang jelas, tidak ada satu pun yang merupakan kapal *terakhir* yang berlayar.

## Solver

```python
import csv, hashlib
from datetime import datetime

CUTOFF = datetime.fromisoformat("2026-10-12T18:00:00+07:00")
PAX = "PX-883"

# 1. Kapal terakhir yang SAILED pada 12 Okt 2026
with open("trip-status.csv", newline="", encoding="utf-8") as f:
    trips = [r for r in csv.DictReader(f)
             if r["date_WIB"] == "2026-10-12"
             and r["status"] == "SAILED"
             and datetime.fromisoformat(r["updated_at"]) <= CUTOFF]
last_trip = max(trips, key=lambda r: r["departure_WIB"])["trip"]

# 2. Versi manifes terakhir <= cutoff untuk trip + penumpang tsb
with open("manifest-versions.csv", newline="", encoding="utf-8") as f:
    rows = [r for r in csv.DictReader(f)
            if r["trip"] == last_trip and r["passenger"] == PAX
            and datetime.fromisoformat(r["version_at"]) <= CUTOFF]
latest = max(rows, key=lambda r: datetime.fromisoformat(r["version_at"]))

answer = f'{latest["trip"]}|{latest["ticket"]}|{latest["state"]}'
digest = hashlib.sha256(answer.encode("utf-8")).hexdigest()
print(answer)
print(f"CF2{{osint_pantai_marina_{digest[:24]}}}")
```

Output:

```
TR-702|0926|boarded
CF2{osint_pantai_marina_1e6a2bc634e8564f0b4f4549}
```

Verifikasi manual:

```bash
$ printf '%s' 'TR-702|0926|boarded' | sha256sum
1e6a2bc634e8564f0b4f45498c13036a8f62267b13733205ea577d21a0983944  -
```

24 karakter pertamanya adalah `1e6a2bc634e8564f0b4f4549`.

## Flag

```
CF2{osint_pantai_marina_1e6a2bc634e8564f0b4f4549}
```
