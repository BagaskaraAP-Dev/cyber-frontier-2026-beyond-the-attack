# Write-up CTF — Tahu Gimbal

## Informasi Soal

- **Nama soal:** Tahu Gimbal
- **Kategori:** OSINT
- **Poin saat diberikan:** 76
- **Lampiran:** `osint-tahu-gimbal-lampiran.zip`
- **File dalam lampiran:** `ulasan.txt`, `direktori.csv`

### Deskripsi

> Ulasan pengunjung menyebut Mas Bambang dengan gerobak hijau di sektor timur. Saat ulasan dibuat, lapaknya masih aktif. Tentukan ID lapak dan nomor tempatnya.

Format jawaban:

```text
CF2{osint_tahu_gimbal_<24 karakter pertama SHA256(ID_LAPAK|NOMOR_TEMPAT)>}
```

Teks `ID_LAPAK|NOMOR_TEMPAT` harus mempertahankan huruf besar/kecil dan nol di depan sesuai sumber, memakai UTF-8, serta tidak mengandung spasi atau newline tambahan.

## Analisis dan Penyelesaian

### 1. Periksa lampiran

Ekstrak arsip ZIP:

```bash
unzip osint-tahu-gimbal-lampiran.zip
```

Ditemukan dua berkas:
- `ulasan.txt` — petunjuk dari ulasan pengunjung.
- `direktori.csv` — daftar identitas dan kondisi setiap lapak.

### 2. Identifikasi petunjuk pada ulasan

Isi `ulasan.txt`:

```text
Ulasan 12 Oktober 2026: Mas Bambang, gerobak hijau, sektor timur. Direktori terlampir berlaku pada tanggal ulasan.
```

Kriteria yang perlu dicocokkan dengan direktori:

1. Pemilik bernama **Bambang**.
2. Warna gerobak **hijau**.
3. Lokasi di sektor **timur**.
4. Status lapak **aktif** pada tanggal ulasan (**12 Oktober 2026**).

Kalimat terakhir pada ulasan menegaskan bahwa direktori terlampir berlaku pada tanggal ulasan, sehingga status dari CSV dapat digunakan secara langsung.

### 3. Cocokkan dengan direktori CSV

Header `direktori.csv`:

```csv
id,owner,cart,sector,stall,status
```

Baris yang memenuhi seluruh petunjuk:

```csv
LP-118,Bambang Tri Laksono,hijau,timur,0427,aktif
```

Hasil identifikasi:

| Kolom | Nilai |
|---|---|
| `id` | `LP-118` |
| `owner` | `Bambang Tri Laksono` |
| `cart` | `hijau` |
| `sector` | `timur` |
| `stall` | `0427` |
| `status` | `aktif` |

**ID lapak = `LP-118`** dan **nomor tempat = `0427`**.

> Penting: nomor tempat `0427` harus diperlakukan sebagai teks. Jika nol di depan hilang, hash yang dihasilkan akan berbeda.

### 4. Buat teks untuk hash

Gabungkan kedua nilai dengan pemisah garis vertikal (`|`), **tanpa spasi maupun newline**:

```text
LP-118|0427
```

### 5. Hitung SHA-256

Contoh memakai Python:

```python
import hashlib

teks = "LP-118|0427"
digest = hashlib.sha256(teks.encode("utf-8")).hexdigest()
print("SHA-256:", digest)
print("24 karakter pertama:", digest[:24])
print(f"CF2{{osint_tahu_gimbal_{digest[:24]}}}")
```

Hasil SHA-256 lengkap:

```text
ae8ce48b3354a033921df804cc94fb92bb61a183eddeb8d450078d77a87d6370
```

Ambil 24 karakter pertama:

```text
ae8ce48b3354a033921df804
```

Alternatif melalui terminal Linux:

```bash
printf '%s' 'LP-118|0427' | sha256sum
```

`printf '%s'` mencegah penambahan newline yang dapat mengubah hash.

## Flag

```text
CF2{osint_tahu_gimbal_ae8ce48b3354a033921df804}
```

## Kesimpulan

Dengan mencocokkan nama pemilik, warna gerobak, sektor, dan status aktif, kandidat yang tepat adalah **`LP-118`** dengan nomor tempat **`0427`**. Gabungan `LP-118|0427` menghasilkan SHA-256 dengan awalan 24 karakter `ae8ce48b3354a033921df804`, sehingga flag adalah:

**`CF2{osint_tahu_gimbal_ae8ce48b3354a033921df804}`**
