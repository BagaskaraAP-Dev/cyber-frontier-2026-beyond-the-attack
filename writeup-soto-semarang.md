# Write-up CTF: Soto Semarang

| Informasi | Detail |
|---|---|
| Nama soal | **Soto Semarang** |
| Kategori | **Miscellaneous (Misc)** |
| Lampiran | `1792902624_misc-soto-semarang-lampiran.zip` |
| Flag | `CF2{misc_soto_semarang_7c98ebfd89841be13c7d}` |

## Deskripsi Soal

> Tampilan kasir memperlihatkan dua label yang nyaris sama. Audit menemukan satu kanal data tersembunyi pada ekspor struk. Pulihkan pesan dari struk aktif.

Tantangannya adalah membedakan dua label yang tampak sama, menentukan baris struk yang benar-benar aktif, kemudian memulihkan data tersembunyi dari kolom angka.

## 1. Analisis Lampiran

Periksa isi arsip:

```bash
unzip -l 1792902624_misc-soto-semarang-lampiran.zip
unzip 1792902624_misc-soto-semarang-lampiran.zip
cat migration.txt
head receipts.csv
```

Arsip memiliki dua file:

- `migration.txt` — keterangan migrasi, arti kolom, dan status struk.
- `receipts.csv` — kumpulan record ekspor kasir.

Menurut `migration.txt`, kolom-kolom CSV adalah:

| Kolom | Fungsi |
|---|---|
| `receipt` | ID struk |
| `position` | Urutan data, dimulai dari 1 |
| `label` | Nama item |
| `value` | Nilai numerik |
| `state` | `approved` = struk sah; `void` = struk dibatalkan |

Karena `void` tidak diekspor ke pembukuan, hanya record dengan status `approved` yang dipakai.

## 2. Menemukan Kanal Tersembunyi

Pada tampilan biasa, nilai kolom `label` tampak seperti **`kuah hangat`**. Namun, sebenarnya terdapat dua jenis pemisah:

```python
"kuah hangat"       # spasi biasa, U+0020
"kuah\u200bhangat"  # ZERO WIDTH SPACE, U+200B
```

Karakter **U+200B (ZERO WIDTH SPACE)** tidak terlihat saat ditampilkan. Inilah pembeda antara data normal dan kanal tersembunyi.

Dari 112 record CSV, didapat:

| Jenis record | Jumlah |
|---|---:|
| `approved` + label dengan U+200B | **65** |
| `approved` + label dengan spasi biasa | 35 |
| `void` + label dengan U+200B | 12 |

Filter yang tepat adalah `state == "approved"` **dan** label mengandung `\u200b`. Hasilnya menghasilkan tepat **65 nilai** dengan posisi lengkap **1–65**. Urutkan record menggunakan `position`, bukan urutan baris mentah CSV karena record disimpan secara acak.

## 3. Dekode Data

Kolom `value` pada 65 record tadi menyimpan byte yang telah di-XOR dengan kunci berdasarkan posisinya.

Untuk setiap record dengan posisi `p` dan nilai `v`, pemulihannya adalah:

```python
byte = v ^ ((p * 13 - 6) & 0xff)
```

Setelah seluruh byte digabungkan menurut urutan posisi, diperoleh teks Base85:

```text
c${-~Gpf$bEKZIu&M(Q2FHX%(EK1Bvk2g=Yv`9@#OR=!DFfmL@H8f5(PpJg}Yn~5d
```

Teks tersebut didekode memakai **Base85** (`base64.b85decode`), lalu hasilnya didekompresi memakai **zlib** (`zlib.decompress`). Dekompresi mengembalikan flag dalam bentuk teks UTF-8.

## 4. Solver Lengkap

Simpan sebagai `solve.py` di folder yang sama dengan file ZIP, lalu jalankan dengan Python 3.

```python
import base64
import csv
import io
import zipfile
import zlib

ARCHIVE = "1792902624_misc-soto-semarang-lampiran.zip"

with zipfile.ZipFile(ARCHIVE) as zf:
    csv_text = zf.read("receipts.csv").decode("utf-8")

rows = list(csv.DictReader(io.StringIO(csv_text)))

# Struk aktif dengan label yang memuat zero-width space.
secret_rows = sorted(
    (
        row
        for row in rows
        if row["state"] == "approved"
        and "\u200b" in row["label"]
    ),
    key=lambda row: int(row["position"]),
)

positions = [int(row["position"]) for row in secret_rows]
assert positions == list(range(1, 66)), "Posisi kanal tersembunyi tidak lengkap"

# Balikkan transformasi XOR untuk setiap posisi (1-based).
encoded = bytes(
    int(row["value"]) ^ ((int(row["position"]) * 13 - 6) & 0xff)
    for row in secret_rows
)

compressed = base64.b85decode(encoded)
flag = zlib.decompress(compressed).decode("utf-8")
print(flag)
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
CF2{misc_soto_semarang_7c98ebfd89841be13c7d}
```

## 5. Kesimpulan

Titik penting penyelesaian soal ini adalah **steganografi teks menggunakan karakter Unicode tak terlihat**. Label `kuah hangat` dengan spasi biasa merupakan pengalih, sedangkan label dengan **U+200B** menyimpan data. Baris `void` juga harus dibuang agar payload tidak rusak. Sesudah memilih 65 baris yang sah, rangkaian transformasi baliknya adalah **urut berdasarkan posisi → XOR → Base85 → zlib → UTF-8**.

## Flag

```text
CF2{misc_soto_semarang_7c98ebfd89841be13c7d}
```
