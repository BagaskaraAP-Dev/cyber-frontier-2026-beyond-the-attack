# Goa Kreo — Writeup

| | |
|---|---|
| **Kategori** | OSINT |
| **Poin** | 388 (awal 500, min 250) |
| **Lampiran** | `osint-goa-kreo-lampiran.zip` |
| **Flag** | `CF2{osint_goa_kreo_74f570cc8952455187961ebf}` |

## Deskripsi Soal

> Atribusikan pemandu BK-5819 dari arsip. Akun berpindah pemilik, lisensi berganti, dan reservasi mengalami perubahan izin. Beberapa log kunjungan yang sah mempunyai waktu dan rute sama. Tentukan kunjungan yang benar berdasarkan izin efektif saat tur dimulai.
>
> Susun `UID|LISENSI_EFEKTIF|TEAM|VISIT|START_UTC` persis sebagai UTF-8 tanpa newline atau spasi tambahan. Kirim `CF2{osint_goa_kreo_<24 karakter pertama SHA256(teks), heksadesimal huruf kecil>}`.

## Isi Lampiran

```
archive-alias.csv        alias,uid,from_utc,until_utc_exclusive
basecamp-log.csv         license,start_utc,route,team,visit,status
booking-amendments.csv   booking,version_at,permit,state
bookings.csv             booking,start_utc,alias,route
license-changes.csv      original_license,effective_license,from_utc,until_utc_exclusive
permit-index.csv         permit,token
profile-export.csv       uid,license_at_profile_export
visit-assignments.csv    token,visit,from_utc,until_utc_exclusive
review.txt
schema.txt
```

`schema.txt` memberikan aturan mainnya:

- Semua timestamp dalam UTC, dengan interval `[from, until)`: `from` ikut dihitung, `until` tidak.
- `profile-export` adalah snapshot lama. Lisensi efektif saat tur harus dicari lewat `license-changes`.
- Untuk booking, pakai versi **confirmed terakhir pada atau sebelum** waktu mulai tur. Versi setelah tur mulai tidak berlaku.
- Rantainya: permit → token (`permit-index`) → visit yang efektif saat tur mulai (`visit-assignments`) → cocokkan visit, lisensi, route, start dan status `completed` di `basecamp-log`.
- Semua ID diperlakukan sebagai teks, jadi nol di depan (misalnya `0741`) tetap dipertahankan.

`review.txt` berisi petunjuknya:

> Ulasan @wisata_lereng: selesai tur yang mulai 12 Oktober 2026 00.20 WIB, jalur Gerbang Atas (GA). Potongan tanda reservasi BK-5819. Pemandu memakai akun @gerbang_senja saat tur berlangsung.

## Penyelesaian

### 1. Waktu mulai tur

12 Oktober 2026 pukul 00.20 WIB (UTC+7) sama dengan **`2026-10-11T17:20:00Z`**. Data ini cocok dengan `bookings.csv`:

```
BK-5819,2026-10-11T17:20:00Z,@gerbang_senja,GA
```

### 2. UID pemilik akun saat tur

```
$ grep gerbang_senja archive-alias.csv
@gerbang_senja,G0721,2026-01-01T00:00:00Z,2026-10-11T18:00:00Z
@gerbang_senja,G0884,2026-10-11T18:00:00Z,2027-01-01T00:00:00Z
```

Akun berpindah tangan pada 18:00Z. Tur mulai 17:20Z, jadi saat itu akun masih milik **`G0721`**. G0884 adalah jebakan.

### 3. Lisensi efektif

```
$ grep G0721 profile-export.csv
G0721,LIC-118

$ grep "^LIC-118," license-changes.csv
LIC-118,LIC-829,2026-10-11T17:00:00Z,2027-01-01T00:00:00Z
LIC-118,LIC-118,2026-01-01T00:00:00Z,2026-10-11T17:00:00Z
```

LIC-118 di snapshot profil sudah usang. Mulai 17:00Z lisensinya dipetakan ke LIC-829, sehingga lisensi efektif saat tur (17:20Z) adalah **`LIC-829`**.

### 4. Permit booking yang berlaku

```
$ grep BK-5819 booking-amendments.csv
BK-5819,2026-10-11T18:10:00Z,PR-81737105,confirmed
BK-5819,2026-10-11T15:00:00Z,PR-81737105,confirmed
BK-5819,2026-10-11T17:10:00Z,PR-60728327,confirmed
```

Diurutkan berdasarkan waktu:

| version_at | permit | keterangan |
|---|---|---|
| 15:00Z | PR-81737105 | sudah digantikan versi berikutnya |
| **17:10Z** | **PR-60728327** | **versi confirmed terakhir ≤ 17:20Z** ✅ |
| 18:10Z | PR-81737105 | setelah tur mulai, tidak berlaku ❌ |

Permit yang berlaku adalah **`PR-60728327`**.

### 5. Permit → token → visit

```
$ grep PR-60728327 permit-index.csv
PR-60728327,AP-c4f24f228781

$ grep AP-c4f24f228781 visit-assignments.csv
AP-c4f24f228781,0741,2026-10-11T17:00:00Z,2027-01-01T00:00:00Z
AP-c4f24f228781,7323,2026-01-01T00:00:00Z,2026-10-11T17:00:00Z
```

Pada 17:20Z, rentang yang aktif adalah `[17:00Z, 2027)`, sehingga visit-nya **`0741`**. Visit 7323 adalah penugasan lama.

### 6. Mencocokkan basecamp log

Jika hanya disaring dengan lisensi, waktu dan rute (`LIC-829`, `17:20Z`, `GA`), muncul **ratusan** baris `completed`. Inilah pengecoh yang dimaksud soal ("beberapa log kunjungan yang sah mempunyai waktu dan rute sama"). Visit menjadi pembeda:

```
$ grep ",0741," basecamp-log.csv
LIC-829,2026-10-11T17:20:00Z,GA,TM-KRO,0741,completed
```

Hasilnya tepat satu baris yang cocok di semua field, dengan team **`TM-KRO`**.

## Ringkasan Rantai

```
review.txt ──► start 2026-10-11T17:20:00Z, GA, @gerbang_senja, BK-5819
archive-alias ──► @gerbang_senja @17:20 = G0721
profile-export ──► G0721 = LIC-118 (snapshot lama)
license-changes ──► LIC-118 @17:20 = LIC-829
booking-amendments ──► BK-5819 confirmed terakhir ≤17:20 = PR-60728327 (17:10)
permit-index ──► PR-60728327 = AP-c4f24f228781
visit-assignments ──► AP-c4f24f228781 @17:20 = visit 0741
basecamp-log ──► LIC-829 / 17:20 / GA / 0741 / completed = TM-KRO
```

## Membuat Flag

```
G0721|LIC-829|TM-KRO|0741|2026-10-11T17:20:00Z
```

```bash
t='G0721|LIC-829|TM-KRO|0741|2026-10-11T17:20:00Z'
printf '%s' "$t" | sha256sum | cut -c1-24
# 74f570cc8952455187961ebf
```

`printf '%s'` dipakai, bukan `echo`, supaya tidak ada newline di akhir teks.

## Flag

```
CF2{osint_goa_kreo_74f570cc8952455187961ebf}
```

## Jebakan yang Perlu Dihindari

- **G0884**: pemilik baru akun, tetapi baru berlaku mulai 18:00Z, setelah tur mulai.
- **LIC-118**: lisensi dari snapshot profil lama, bukan lisensi efektif.
- **PR-81737105**: permit dari amandemen 18:10Z, yang terjadi setelah tur mulai.
- **Visit 7323**: penugasan token sebelum 17:00Z.
- **Ratusan log LIC-829/GA/17:20**: hanya visit 0741 yang benar.
- **Zona waktu**: 00.20 WIB adalah 17:20Z pada hari **sebelumnya** (11 Oktober).
