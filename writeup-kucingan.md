# Kucingan — Writeup

**Kategori:** OSINT
**Poin:** 174 (awal 250, min 125)
**Flag:** `CF2{osint_kucingan_304acad5fac477f4232a955e}`

## Deskripsi Soal

> Foto gerobak diunggah tanpa nama tempat. Tentukan gerai aktif terdekat saat foto diambil. EXIF waktu kamera memakai WIB; masa berlaku gerai menggunakan tanggal WIB.
>
> Jawaban: susun `ID_GERAI|OPERATOR|YYYY-MM-DD` dari bukti. Gunakan huruf besar/kecil persis seperti sumber, tanpa spasi tambahan, UTF-8, tanpa newline. Kirim `CF2{osint_kucingan_<24 karakter pertama SHA256(teks tersebut), heksadesimal huruf kecil>}`.

## Lampiran

Isi `osint-kucingan-lampiran.zip`:

| File | Isi |
|---|---|
| `gerobak.jpg` | Foto gerobak (gambar polos bertuliskan "ANGKRINGAN / LABCF26") beserta metadata EXIF |
| `gerai.csv` | Daftar 43 gerai: `id, lat, lon, from_date, until_date_exclusive, operator` |
| `kebijakan.txt` | Aturan pemilihan gerai |

Isi `kebijakan.txt`:

```
Koordinat gerai berupa WGS84. Pilih gerai aktif pada tanggal foto, lalu jarak geodesik terdekat.
Interval tanggal [from_date, until_date_exclusive). Operator dapat berganti.
Semua lokasi dan operator merupakan simulasi.
```

Ada tiga aturan penting dari file ini:
1. Gerai disaring dulu berdasarkan **status aktif** pada tanggal foto, baru setelah itu dicari yang **terdekat**.
2. Intervalnya **setengah terbuka**: `from_date ≤ tanggal < until_date_exclusive`.
3. Jarak dihitung secara **geodesik** di elipsoid WGS84.

## Langkah 1: Baca EXIF foto

```
$ exiftool gerobak.jpg
Modify Date      : 2026:10:12 00:05:00
GPS Latitude Ref : South
GPS Latitude     : 6 deg 58' 3.00"
GPS Longitude Ref: East
GPS Longitude    : 110 deg 25' 1.00"
```

Konversi koordinat ke derajat desimal:

- Lat = −(6 + 58/60 + 3/3600) = **−6.9675000**
- Lon = 110 + 25/60 + 1/3600 = **110.4169444**

Foto diambil pada **2026-10-12 00:05 WIB**. Menurut soal, EXIF sudah dalam WIB dan masa berlaku gerai juga memakai tanggal WIB, jadi tidak perlu konversi zona waktu. Tanggal yang dipakai adalah **2026-10-12**.

## Langkah 2: Jebakan

Koordinat foto **sama persis** dengan gerai **K040**:

```
K040,-6.9675000,110.4169444,2026-10-01,2026-10-11,A40
```

Jaraknya 0 m, tetapi `until_date_exclusive = 2026-10-11`, sehingga K040 hanya aktif sampai 2026-10-10. Pada 2026-10-12 gerai ini **sudah tidak aktif**. Kalau langsung mencari gerai terdekat tanpa menyaring status aktif, jawabannya akan salah.

Jam foto `00:05` juga sengaja dipasang mepet tengah malam. Kalau waktu ini dianggap UTC lalu dikonversi ke WIB, atau sebaliknya, tanggalnya bisa bergeser. Soal sudah menyatakan semuanya memakai WIB, jadi tanggal yang benar tetap 2026-10-12.

Gerai lain yang gugur karena sudah berakhir sebelum tanggal foto: K013, K016, K017, K019, K025, K033, K035, K040 (semua `until_date_exclusive ≤ 2026-10-11`).

## Langkah 3: Saring gerai aktif lalu hitung jarak geodesik

Script solver (memakai `geographiclib` untuk geodesik WGS84):

```python
import csv, hashlib
from geographiclib.geodesic import Geodesic

lat = -(6 + 58/60 + 3/3600)
lon = 110 + 25/60 + 1/3600
tgl = "2026-10-12"

aktif = [r for r in csv.DictReader(open("gerai.csv"))
         if r["from_date"] <= tgl < r["until_date_exclusive"]]

hasil = sorted(
    (Geodesic.WGS84.Inverse(lat, lon, float(r["lat"]), float(r["lon"]))["s12"],
     r["id"], r["operator"])
    for r in aktif
)

for h in hasil[:5]:
    print(h)

jarak, gid, op = hasil[0]
teks = f"{gid}|{op}|{tgl}"
print(teks)
print(f"CF2{{osint_kucingan_{hashlib.sha256(teks.encode()).hexdigest()[:24]}}}")
```

Output:

```
(6.25, 'K011', 'A11')
(23.45, 'K027', 'A27')
(44.02, 'K028', 'A28')
(216.19, 'K041', 'A41')
(417.91, 'K018', 'A18')
K011|A11|2026-10-12
CF2{osint_kucingan_304acad5fac477f4232a955e}
```

Ringkasan kandidat di sekitar lokasi foto:

| ID | Operator | Masa berlaku | Aktif 2026-10-12? | Jarak |
|---|---|---|---|---|
| K040 | A40 | 2026-10-01 → 2026-10-11 | ❌ | 0 m |
| **K011** | **A11** | 2026-10-01 → 2026-11-01 | ✅ | **6,25 m** |
| K027 | A27 | 2026-10-01 → 2026-11-01 | ✅ | 23,45 m |
| K028 | A28 | 2026-09-28 → 2026-10-25 | ✅ | 44,02 m |
| K025 | A25 | 2026-10-05 → 2026-10-11 | ❌ | — |
| K017 | A17 | 2026-10-01 → 2026-10-11 | ❌ | — |

Gerai aktif terdekat adalah **K011** dengan operator **A11**.

## Langkah 4: Susun jawaban

```
K011|A11|2026-10-12
```

Hash dengan SHA256 (UTF-8, tanpa newline), lalu ambil 24 karakter pertama:

```
$ printf '%s' 'K011|A11|2026-10-12' | sha256sum | cut -c1-24
304acad5fac477f4232a955e
```

## Flag

```
CF2{osint_kucingan_304acad5fac477f4232a955e}
```

## Pelajaran

- Gerai yang lokasinya paling cocok belum tentu jawabannya. Cek dulu **validitas waktu**-nya.
- Perhatikan interval **setengah terbuka** `[from, until)`: tanggal `until_date_exclusive` sendiri tidak ikut terhitung aktif.
- Waktu yang mepet tengah malam adalah jebakan klasik soal zona waktu. Pastikan EXIF dan data referensi memakai zona waktu yang sama.
- Pakai jarak **geodesik WGS84**, bukan jarak Euclid pada lat/lon mentah, apalagi kalau jarak antar kandidat hanya belasan meter.
