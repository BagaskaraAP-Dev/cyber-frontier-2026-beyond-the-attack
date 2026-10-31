# Writeup CTF — Bandeng Presto

**Kategori:** Cryptography  
**Nama soal:** Bandeng Presto  
**Flag:** `CF2{bandeng_presto_934e1e05dfaccf58f01482c3}`

## Deskripsi singkat

Kita diminta memulihkan plaintext arsip `BP-POOL` dari beberapa kapsul perangkat. Arsip menggunakan **Shamir Secret Sharing (2-of-5)**, tetapi ada satu share yang dimodifikasi sehingga tidak cocok dengan *provisioning commitment*. Kita harus memvalidasi setiap share, mengambil dua share yang valid, memulihkan secret, memverifikasi HMAC, lalu mendekripsi ciphertext. Flag diperoleh dari 24 karakter pertama SHA-256 atas byte plaintext UTF-8 **tanpa newline**.

## Berkas lampiran

Arsip `bandeng-presto-lampiran.zip` berisi:

- `recovery-spec.txt` — aturan validasi, interpolasi, keystream, dan HMAC.
- `device-shares.csv` — lima share perangkat dan commitment masing-masing.
- `archive.enc` — ciphertext heksadesimal beserta HMAC-SHA256.

Ekstrak berkas dengan:

```bash
unzip bandeng-presto-lampiran.zip -d bandeng-presto
cd bandeng-presto
```

## 1. Membaca skema

Dari `recovery-spec.txt`:

1. Setiap byte secret dibagikan menggunakan Shamir Secret Sharing dengan ambang **2 dari 5** di medan `GF(2^8)`, polinomial irreducible `0x11B`.
2. Penjumlahan di medan ini adalah operasi **XOR**, sedangkan perkalian direduksi modulo `0x11B`.
3. Commitment share dihitung sebagai:

   ```text
   SHA256(ASCII_decimal_x || b":" || raw_y_bytes)
   ```

4. Dua share sah dengan koordinat `x` berbeda cukup untuk menginterpolasi polinomial derajat satu dan mendapatkan `f(0)`, yaitu secret.
5. Keystream enkripsi dibentuk dengan menggabungkan `SHA256(secret || counter32be)` untuk counter mulai dari nol, lalu dipotong sesuai panjang ciphertext.
6. HMAC-SHA256 dihitung dengan **secret sebagai kunci** dan **ciphertext sebagai pesan**. Verifikasi harus berhasil sebelum plaintext diterima.

## 2. Memverifikasi commitment kapsul

Untuk setiap baris `device-shares.csv`, hitung SHA-256 dari `str(x).encode('ascii') + b':' + bytes.fromhex(share_hex)` lalu bandingkan dengan `provisioning_commitment_sha256`.

Hasil:

| Kapsul | Hasil commitment |
|---|---|
| BP-01 | Valid |
| BP-02 | Valid |
| BP-03 | Valid |
| **BP-04** | **Tidak valid (ditolak)** |
| BP-05 | Valid |

Untuk `BP-04` ditemukan:

```text
Commitment yang disimpan:
5687732ffd8c85fade6b09cc8e4a057d7ef9a67a0353745b357b3f5182b8bd6d

SHA-256 commitment yang dihitung:
64a3df8972fbe723c94dfbdc3c93f0f6ed7a6ef1ebbc189d20205463fa9932df
```

Karena kedua nilai berbeda, **BP-04 adalah kapsul rusak/pengecoh** dan tidak boleh digunakan untuk rekonstruksi.

## 3. Rekonstruksi secret dengan dua share sah

Gunakan `BP-01` dan `BP-02`:

```text
BP-01: x = 1, y = 1f3f5f7f9fbfdfff8f2f4f6f8fafcfef
BP-02: x = 2, y = 88ee80dada98d634350fd55c7bc35266
```

Pada setiap posisi byte, polinomial derajat satu mempunyai bentuk `f(x) = a*x + s`, dengan `s = f(0)` sebagai byte secret. Rumus interpolasi pada `x=0`:

```text
s = y1 * x2 / (x1 XOR x2) XOR y2 * x1 / (x1 XOR x2)
```

Seluruh operasi perkalian/pembagian dilakukan di `GF(2^8)`, bukan aritmetika bilangan bulat biasa. Hasil secret 16 byte:

```text
9b70e31c55a2d84f10c6397e2a8b4d61
```

## 4. Verifikasi HMAC dan dekripsi arsip

`archive.enc` menyimpan:

```text
ciphertext_hex = 62fbd1d047274b1daaf09d01d0e35dd98da05100f9364f1b13412a4e5c
hmac_sha256    = 70ccdec8e3c1ca94989a188e9974c2022ec96c037ab48d9dc626164e35291e56
```

Verifikasi HMAC menggunakan secret sebagai kunci menghasilkan nilai identik dengan HMAC dalam berkas, sehingga ciphertext autentik.

Selanjutnya buat keystream dari `SHA256(secret || counter32be)` dan lakukan XOR dengan ciphertext. Plaintext yang diperoleh:

```text
BP-POOL|R-73|restore=complete
```

## 5. Menghitung flag

SHA-256 dari plaintext UTF-8 tanpa newline adalah:

```text
934e1e05dfaccf58f01482c3e2532b2ec4dd6d3834af9fc56a902673337e0d5c
```

Ambil **24 karakter pertama**:

```text
934e1e05dfaccf58f01482c3
```

Flag akhir:

```text
CF2{bandeng_presto_934e1e05dfaccf58f01482c3}
```

## Solver Python (standard library)

Simpan skrip berikut sebagai `solve.py` di folder hasil ekstraksi dan jalankan dengan `python3 solve.py`.

```python
import csv
import hashlib
import hmac
import json


def gf_mul(a, b):
    """Perkalian GF(2^8), polinomial reduksi 0x11B."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


def gf_pow(a, n):
    result = 1
    while n:
        if n & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        n >>= 1
    return result


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError("Pembagian dengan nol di GF(2^8)")
    # GF(256): b^-1 = b^254 untuk b != 0.
    return gf_mul(a, gf_pow(b, 254))


# 1. Validasi semua kapsul.
valid_shares = []
with open("device-shares.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        x = int(row["x"])
        y = bytes.fromhex(row["share_hex"])
        digest = hashlib.sha256(str(x).encode("ascii") + b":" + y).hexdigest()
        is_valid = hmac.compare_digest(digest, row["provisioning_commitment_sha256"])
        print(f"{row['device']}: {'VALID' if is_valid else 'INVALID'}")
        if is_valid:
            valid_shares.append((x, y))

assert len(valid_shares) >= 2, "Kapsul sah tidak cukup"

# 2. Interpolasi f(0) menggunakan dua kapsul sah.
(x1, y1), (x2, y2) = valid_shares[:2]
assert x1 != x2 and len(y1) == len(y2)
secret = bytes(
    gf_div(gf_mul(v1, x2), x1 ^ x2)
    ^ gf_div(gf_mul(v2, x1), x1 ^ x2)
    for v1, v2 in zip(y1, y2)
)
print("Secret:", secret.hex())

# 3. Validasi MAC atas ciphertext SEBELUM menerima plaintext.
with open("archive.enc", encoding="utf-8") as f:
    archive = json.load(f)
ciphertext = bytes.fromhex(archive["ciphertext_hex"])
expected_mac = bytes.fromhex(archive["hmac_sha256"])
actual_mac = hmac.new(secret, ciphertext, hashlib.sha256).digest()
assert hmac.compare_digest(actual_mac, expected_mac), "HMAC tidak valid"
print("HMAC: VALID")

# 4. Keystream SHA-256(secret || counter32be), counter mulai 0.
keystream = b"".join(
    hashlib.sha256(secret + i.to_bytes(4, "big")).digest()
    for i in range((len(ciphertext) + 31) // 32)
)[:len(ciphertext)]
plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
message = plaintext.decode("utf-8")
print("Plaintext:", message)

# 5. Hash atas byte persis (jangan tambah newline).
sha256_hex = hashlib.sha256(plaintext).hexdigest()
flag = f"CF2{{bandeng_presto_{sha256_hex[:24]}}}"
print("SHA-256:", sha256_hex)
print("FLAG:", flag)
```

### Contoh output

```text
BP-01: VALID
BP-02: VALID
BP-03: VALID
BP-04: INVALID
BP-05: VALID
Secret: 9b70e31c55a2d84f10c6397e2a8b4d61
HMAC: VALID
Plaintext: BP-POOL|R-73|restore=complete
SHA-256: 934e1e05dfaccf58f01482c3e2532b2ec4dd6d3834af9fc56a902673337e0d5c
FLAG: CF2{bandeng_presto_934e1e05dfaccf58f01482c3}
```

## Kesimpulan

Inti soal adalah **memvalidasi share sebelum melakukan rekonstruksi**. `BP-04` ditolak karena commitment tidak cocok. Dari dua share sah `BP-01` dan `BP-02`, secret berhasil dipulihkan lewat interpolasi Shamir di `GF(2^8)`. HMAC yang cocok membuktikan ciphertext autentik, lalu dekripsi keystream XOR menghasilkan plaintext arsip. Hash dari byte plaintext yang persis memberi flag yang benar.
