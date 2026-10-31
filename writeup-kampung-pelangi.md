# Kampung Pelangi

| | |
|---|---|
| **Kategori** | OSINT |
| **Poin** | 225 (awal 300, min 150) |
| **Solve** | 15 |
| **First blood** | Raksa |
| **Flag** | `CF2{kampung_pelangi_74c32387760628b6ec0dcdfc}` |

## Deskripsi

> Arsip simulasi berisi riwayat alias, kontak, dan registrasi. Atribusikan unggahan `@pelangi_utara` pada waktu yang tercantum di `files/post.txt`.
>
> Tentukan UID pemilik alias, lalu entity dan slot yang berlaku melalui riwayat kontak dan registry. Jangan memakai status terbaru bila waktunya berbeda. Aturan interval dan normalisasi ada di `files/rules.txt`.
>
> Jawaban kanonis: `UID|ENTITY|SLOT`, persis seperti sumber tanpa spasi atau newline.
>
> Format flag: `CF2{kampung_pelangi_<24 karakter pertama SHA256(jawaban UTF-8), heksadesimal huruf kecil>}`

## Isi lampiran

```
kampung-pelangi-lampiran.zip
├── post.txt
├── rules.txt
├── alias-history.csv
├── contact-history.csv
└── registry.csv
```

**post.txt**

```
Platform capture: @pelangi_utara published at 2026-10-12 01:30 WIB.
```

**rules.txt**

```
Temporal rules

All timestamps are UTC. Validity intervals are half-open: valid_from <=
event_time < valid_until. An empty valid_until means no recorded end.
Resolve the alias owner at publication time, then the contact binding for
that UID at the same instant, then the registry row for that contact at the
same instant. Return UID|ENTITY|SLOT using exact source spelling.
Hash the UTF-8 bytes of that string, with no newline, and use the first
24 lowercase hexadecimal SHA-256 characters in the flag.
```

**alias-history.csv**

```
alias,uid,valid_from_utc,valid_until_utc,source
@pelangi_utara,UID-117,2026-01-01T00:00:00Z,2026-10-11T18:00:00Z,legacy
@pelangi_utara,UID-204,2026-10-11T18:00:00Z,2026-10-11T20:00:00Z,transfer
@pelangi_utara,UID-311,2026-10-11T20:00:00Z,,current
@pelangi_selatan,UID-204,2026-01-01T00:00:00Z,,unrelated
```

**contact-history.csv**

```
uid,contact_id,valid_from_utc,valid_until_utc,record_id
UID-117,CONTACT-22,2026-01-01T00:00:00Z,,C-OLD
UID-204,CONTACT-41,2026-10-11T17:00:00Z,2026-10-11T19:00:00Z,C-TRANSFER
UID-204,CONTACT-88,2026-10-11T19:00:00Z,,C-NEW
UID-311,CONTACT-55,2026-10-11T20:00:00Z,,C-LATER
```

**registry.csv**

```
contact_id,entity,slot,valid_from_utc,valid_until_utc,revision
CONTACT-41,ENTITY-PELANGI-07,SLOT-014,2026-10-11T18:00:00Z,2026-10-11T19:00:00Z,approved
CONTACT-41,ENTITY-PELANGI-70,SLOT-041,2026-10-11T19:00:00Z,,superseded
CONTACT-88,ENTITY-PELANGI-08,SLOT-088,2026-10-11T19:00:00Z,,current
CONTACT-22,ENTITY-PELANGI-02,SLOT-002,2026-01-01T00:00:00Z,,legacy
CONTACT-55,ENTITY-PELANGI-55,SLOT-055,2026-10-11T20:00:00Z,,current
```

## Penyelesaian

Soal ini adalah *temporal join* tiga tahap: alias → UID → contact → entity/slot. Semua tahap harus dicocokkan pada **satu waktu yang sama**, yaitu waktu unggahan.

### 1. Konversi waktu unggahan ke UTC

`post.txt` memakai **WIB (UTC+7)**, sedangkan `rules.txt` menyatakan semua timestamp di arsip memakai UTC.

```
2026-10-12 01:30 WIB  →  2026-10-11T18:30:00Z
```

Ini jebakan utamanya. Kalau `01:30` dibaca langsung sebagai UTC tanggal 12, semua lookup akan jatuh ke baris "current" dan jawabannya salah.

### 2. Pemilik alias saat 18:30Z

Interval berbentuk *half-open*: `valid_from <= t < valid_until`.

| alias | uid | interval | cocok dengan 18:30Z? |
|---|---|---|---|
| @pelangi_utara | UID-117 | 01-01 00:00 → 10-11 18:00 | ✗ (berakhir tepat 18:00) |
| @pelangi_utara | **UID-204** | 10-11 18:00 → 10-11 20:00 | ✓ |
| @pelangi_utara | UID-311 | 10-11 20:00 → ∞ | ✗ (belum mulai) |

→ **UID-204**. UID-311 adalah pemilik terbaru, jadi menjadi pengecoh "status terbaru" yang disebut di deskripsi. Baris `@pelangi_selatan` juga milik UID-204, tetapi alias itu tidak relevan.

### 3. Kontak UID-204 saat 18:30Z

| uid | contact_id | interval | cocok? |
|---|---|---|---|
| UID-204 | **CONTACT-41** | 10-11 17:00 → 10-11 19:00 | ✓ |
| UID-204 | CONTACT-88 | 10-11 19:00 → ∞ | ✗ |

→ **CONTACT-41**

### 4. Baris registry CONTACT-41 saat 18:30Z

| contact_id | entity | slot | interval | cocok? |
|---|---|---|---|---|
| CONTACT-41 | **ENTITY-PELANGI-07** | **SLOT-014** | 10-11 18:00 → 10-11 19:00 | ✓ |
| CONTACT-41 | ENTITY-PELANGI-70 | SLOT-041 | 10-11 19:00 → ∞ | ✗ |

→ **ENTITY-PELANGI-07 / SLOT-014**. Baris `PELANGI-70 / SLOT-041` sengaja dibuat mirip (digitnya dibalik) untuk menjebak yang salah baca atau memakai baris terakhir.

### 5. Jawaban kanonis dan hash

```
UID-204|ENTITY-PELANGI-07|SLOT-014
```

```bash
$ printf '%s' 'UID-204|ENTITY-PELANGI-07|SLOT-014' | sha256sum | cut -c1-24
74c32387760628b6ec0dcdfc
```

Pakai `printf '%s'` atau `echo -n` agar tidak ada newline yang ikut di-hash.

### Solver (Python)

```python
import csv, hashlib
from datetime import datetime, timedelta, timezone

def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None

def at(rows, t):
    return [r for r in rows
            if ts(r["valid_from_utc"]) <= t
            and (not r["valid_until_utc"] or t < ts(r["valid_until_utc"]))]

load = lambda f: list(csv.DictReader(open(f)))
alias, contact, registry = (load(f) for f in
    ("alias-history.csv", "contact-history.csv", "registry.csv"))

wib = timezone(timedelta(hours=7))
t = datetime(2026, 10, 12, 1, 30, tzinfo=wib).astimezone(timezone.utc)

uid = at([r for r in alias if r["alias"] == "@pelangi_utara"], t)[0]["uid"]
cid = at([r for r in contact if r["uid"] == uid], t)[0]["contact_id"]
reg = at([r for r in registry if r["contact_id"] == cid], t)[0]

ans = f"{uid}|{reg['entity']}|{reg['slot']}"
print(ans)
print("CF2{kampung_pelangi_" + hashlib.sha256(ans.encode()).hexdigest()[:24] + "}")
```

Output:

```
UID-204|ENTITY-PELANGI-07|SLOT-014
CF2{kampung_pelangi_74c32387760628b6ec0dcdfc}
```

## Flag

```
CF2{kampung_pelangi_74c32387760628b6ec0dcdfc}
```

## Ringkasan jebakan

- **Zona waktu:** post dalam WIB, data dalam UTC (selisih 7 jam, dan tanggalnya ikut mundur sehari).
- **Status terbaru:** UID-311, CONTACT-88, dan baris `superseded` semuanya baris "terbaru" yang salah untuk waktu unggahan.
- **Batas half-open:** UID-117 berakhir tepat 18:00, jadi tidak berlaku lagi.
- **Angka mirip:** `PELANGI-07/SLOT-014` vs `PELANGI-70/SLOT-041`.
