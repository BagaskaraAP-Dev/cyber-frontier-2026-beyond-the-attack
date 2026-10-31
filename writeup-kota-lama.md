# Write-up CTF — Kota Lama

| Informasi | Detail |
|---|---|
| Nama soal | **Kota Lama** |
| Kategori | **Digital Forensics** |
| Lampiran | `kota-lama-lampiran.zip` |
| Teknik | Chain of custody, SHA-256, LSB steganography pada kanal RGB |
| Flag | `CF2{kota_lama_0b4f827d6420e7b43df1fa64}` |

## Deskripsi Soal

Tiga berkas gambar ditemukan dalam satu arsip. Kita diminta menggunakan *chain of custody* untuk memilih **salinan kamera asli**, bukan berkas turunan ataupun scan independen yang memuat pesan pengecoh.

Pada gambar asli, pesan disembunyikan melalui **least significant bit (LSB)** dari setiap kanal **R, G, B**, dibaca berurutan dari kiri ke kanan dan atas ke bawah. Setiap byte dibentuk dengan urutan **MSB-first**, dan pesan berakhir pada **byte NUL (`0x00`) pertama**.

Format flag:

```text
CF2{kota_lama_<24_karakter_pertama_SHA256_pesan>}
```

Hash SHA-256 dihitung atas byte ASCII pesan **tanpa newline**.

## 1. Identifikasi Berkas Lampiran

Tampilkan isi arsip:

```bash
unzip -l kota-lama-lampiran.zip
```

Isi arsip:

```text
capture-101.png
capture-102.png
capture-103.png
chain-of-custody.csv
```

Ekstrak lampiran dan baca catatan rantai penguasaan:

```bash
unzip kota-lama-lampiran.zip -d kota_lama
cat kota_lama/chain-of-custody.csv
```

Catatan penting:

| Waktu (UTC) | Objek | Operasi | Berkas hasil |
|---|---|---|---|
| `2026-10-11T16:10:00Z` | `CAM-41/ORIGINAL` | `camera_ingest` | `capture-101.png` |
| `2026-10-11T16:42:00Z` | `CAM-41/PREVIEW` | `resize_and_reencode` | `capture-102.png` |
| `2026-10-11T17:05:00Z` | `ARCHIVE/SCAN` | `independent_scan` | `capture-103.png` |

Baris `CAM-41/ORIGINAL` menentukan bahwa **`capture-101.png` adalah gambar asli**. `capture-102.png` adalah berkas turunan, sedangkan `capture-103.png` merupakan scan independen.

## 2. Verifikasi SHA-256 Gambar Asli

Catatan `CAM-41/ORIGINAL` menyebut nilai `input_sha256`:

```text
811a186a0fe2ceac504186d158002777b0ae3c09d20abfc056e42a9827cc9604
```

Periksa hash berkas:

```bash
sha256sum kota_lama/capture-101.png
```

Hasil:

```text
811a186a0fe2ceac504186d158002777b0ae3c09d20abfc056e42a9827cc9604  kota_lama/capture-101.png
```

Nilai hash **cocok** dengan catatan asal, sehingga kita lanjut menggunakan `capture-101.png`.

## 3. Ekstraksi Pesan dari LSB RGB

Setiap piksel menyimpan tiga kanal warna: merah (R), hijau (G), dan biru (B). Satu bit diperoleh dari setiap kanal menggunakan operasi `nilai_kanal & 1`.

Aturan pembacaan:

1. Iterasi piksel **baris demi baris**, dari atas ke bawah; dalam setiap baris dari kiri ke kanan.
2. Dari setiap piksel, ambil bit LSB dalam urutan **R → G → B**.
3. Gabungkan setiap delapan bit menjadi satu byte, **bit yang pertama dibaca menjadi MSB**.
4. Berhenti ketika menemukan byte `0x00`; jangan sertakan byte NUL dalam pesan.

Berikut skrip Python yang langsung membaca berkas dari ZIP, mengecek rantai penguasaan dan hash, mengekstrak pesan, lalu mencetak flag.

> Prasyarat: Python 3 dan Pillow (`python -m pip install pillow`). Simpan kode di bawah sebagai `solve.py` dan tempatkan ZIP pada direktori yang sama.

```python
import csv
import hashlib
import io
import zipfile
from PIL import Image

ARCHIVE = "kota-lama-lampiran.zip"

with zipfile.ZipFile(ARCHIVE) as zf:
    custody = zf.read("chain-of-custody.csv").decode("utf-8")
    records = list(csv.DictReader(io.StringIO(custody)))

    original = next(
        row for row in records
        if row["object"] == "CAM-41/ORIGINAL"
        and row["operation"] == "camera_ingest"
    )
    filename = original["output_file"]
    image_bytes = zf.read(filename)

    actual_hash = hashlib.sha256(image_bytes).hexdigest()
    assert actual_hash == original["input_sha256"], "Hash gambar tidak cocok!"

image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
width, height = image.size

# RGB berurutan, piksel kiri-ke-kanan dan atas-ke-bawah.
bits = (
    channel & 1
    for y in range(height)
    for x in range(width)
    for channel in image.getpixel((x, y))
)

message = bytearray()
current_byte = 0
bit_count = 0

for bit in bits:
    # Bit lebih awal menjadi posisi paling signifikan (MSB).
    current_byte = (current_byte << 1) | bit
    bit_count += 1

    if bit_count == 8:
        if current_byte == 0:  # terminator NUL
            break
        message.append(current_byte)
        current_byte = 0
        bit_count = 0

plaintext = message.decode("ascii")
digest = hashlib.sha256(message).hexdigest()
flag = f"CF2{{kota_lama_{digest[:24]}}}"

print("Original  :", filename)
print("Message   :", plaintext)
print("SHA-256   :", digest)
print("Flag      :", flag)
```

Jalankan:

```bash
python solve.py
```

Output:

```text
Original  : capture-101.png
Message   : KL-ORIGINAL-7F2A
SHA-256   : 0b4f827d6420e7b43df1fa642def86f6b0e55e0819fb67e5e4207e7bae75da2c
Flag      : CF2{kota_lama_0b4f827d6420e7b43df1fa64}
```

## 4. Mengapa Gambar Lain Salah?

Sebagai verifikasi, metode LSB yang sama bila diterapkan pada gambar lain menghasilkan pesan berbeda:

| Berkas | Pesan LSB | Status |
|---|---|---|
| `capture-101.png` | `KL-ORIGINAL-7F2A` | **Valid, kamera asli** |
| `capture-102.png` | `KL-PREVIEW-DECOY` | Pengecoh, preview turunan |
| `capture-103.png` | `KL-SCAN-NO-RECORD` | Pengecoh, scan independen |

Artinya, **ekstraksi LSB saja tidak cukup**. Identifikasi sumber berdasarkan catatan *chain of custody* merupakan inti dari soal ini.

## 5. Perhitungan Flag

Pesan yang valid:

```text
KL-ORIGINAL-7F2A
```

SHA-256 atas byte ASCII pesan tersebut, tanpa NUL dan tanpa newline:

```text
0b4f827d6420e7b43df1fa642def86f6b0e55e0819fb67e5e4207e7bae75da2c
```

Ambil **24 karakter heksadesimal pertama**:

```text
0b4f827d6420e7b43df1fa64
```

Susun sesuai format soal.

## Flag Akhir

```text
CF2{kota_lama_0b4f827d6420e7b43df1fa64}
```

## Kesimpulan

Soal **Kota Lama** menggabungkan analisis *chain of custody*, pemeriksaan integritas SHA-256, dan steganografi LSB RGB. Dengan memverifikasi bahwa `capture-101.png` merupakan salinan kamera asli, kita dapat mengabaikan dua pesan pengecoh, membaca pesan ASCII yang benar, dan menghasilkan flag sesuai ketentuan.
