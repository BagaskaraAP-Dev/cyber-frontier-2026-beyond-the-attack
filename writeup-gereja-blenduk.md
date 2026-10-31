# Writeup — Gereja Blenduk

- **Kategori:** Reverse Engineering
- **Poin:** 290 (awal 300, min 150) · 2 solve
- **Flag:** `CF2{rev_gereja_blenduk_de2fe1fb3466b18bfaaa}`
- **Serial:** `YLpaZdJg`

---

## Deskripsi

> Validator arsip baru tidak lagi memeriksa setiap karakter secara terpisah. Pulihkan serial delapan byte yang memenuhi seluruh pemeriksaan, lalu buka vault. Runtime tersedia sebagai spesifikasi perilaku; analisis statis diperbolehkan.

Lampiran:

| File | Isi |
|------|-----|
| `runtime.py` | Spesifikasi perilaku validator + dekripsi vault |
| `program.bin` | 148 byte: header `BLV5` + 72 nilai `uint16` |
| `vault.json` | Ciphertext ter-XOR keystream (hex) |

---

## Analisis

Karena `runtime.py` diberikan sebagai spesifikasi, soal ini murni *static analysis* — tidak perlu debugging binary. Isi intinya:

```python
s = sys.argv[1].encode('ascii')          # serial, HARUS 8 byte ASCII
b = (p/'program.bin').read_bytes()
if len(b)!=148 or b[:4]!=b'BLV5': ...     # validasi program
a = struct.unpack('<72H', b[4:])          # 72 uint16 little-endian
v = [(x*197+31)&255 for x in s]           # transform tiap byte serial
for i in range(8):
    if sum(a[8*i+j]*v[j] for j in range(8)) % 257 != a[64+i]:
        raise SystemExit('serial rejected')
# ... lolos semua cek → dekripsi vault
x = bytes.fromhex(json.loads(...)['ciphertext_hex'])
k = hashlib.sha256(s).digest()
z = b''.join(hashlib.sha256(k+i.to_bytes(4,'big')).digest()
             for i in range((len(x)+31)//32))
print(bytes(a^b for a,b in zip(x,z)).decode())
```

### Membongkar strukturnya

`program.bin` = `BLV5` (4 byte) + 144 byte = **72 nilai `uint16` little-endian** `a[0..71]`. Nilai-nilai itu dipecah jadi:

- `a[0..63]`  → matriks **M** berukuran 8×8, dengan `M[i][j] = a[8i+j]`
- `a[64..71]` → vektor target **t** panjang 8

Serial diubah dulu per byte:

```
v[j] = (s[j]·197 + 31) mod 256
```

Lalu syarat lolosnya, untuk setiap baris `i`:

```
Σ_j  M[i][j]·v[j]  ≡  t[i]   (mod 257)
```

Itulah maksud *"tidak lagi memeriksa setiap karakter secara terpisah"*: validator lama kemungkinan mengecek tiap byte sendiri-sendiri (gampang di-brute per karakter), sementara versi baru menggabungkannya menjadi **sistem persamaan linear**:

```
M · v ≡ t   (mod 257)
```

Semua 8 byte saling terkait, jadi brute-force per-byte tidak lagi mempan.

---

## Solusi

Dua langkah aljabar, tanpa brute-force ruang 2⁶⁴.

### 1. Selesaikan sistem linear mod 257

257 adalah **bilangan prima**, sehingga `ℤ/257ℤ` adalah *field* dan eliminasi Gauss bekerja (inversi lewat Teorema Kecil Fermat, `inv(x) = x^(P−2) mod P`). Selesaikan `M·v ≡ t (mod 257)`:

```
v = [156, 155, 79, 196, 97, 19, 17, 98]
```

Catatan penting: karena `v[j]` aslinya hasil `& 255` (jadi 0–255) dan `257 > 256`, solusi mod 257 langsung bernilai sama dengan `v[j]` yang sebenarnya — selama hasilnya `< 256` (tervalidasi: semua `≤ 196`).

### 2. Balik transformasi `v → s`

```
v[j] = (s[j]·197 + 31) mod 256
```

Transformasi ini invertibel karena `gcd(197, 256) = 1` (197 ganjil). Dengan `inv(197) mod 256 = 109`:

```
s[j] = (v[j] − 31) · 109  mod 256
```

Hasilnya:

```
s = [89, 76, 112, 97, 90, 100, 74, 103]  →  "YLpaZdJg"
```

Kebetulan kedelapan byte jatuh di rentang ASCII printable, konsisten dengan syarat "8 byte ASCII".

### 3. Buka vault

Masukkan serial ke `runtime.py`. Setelah cek lolos, vault didekripsi dengan keystream SHA-256 counter-mode:

- `k = sha256(serial)`
- blok keystream ke-`i` = `sha256(k ‖ i_be32)`
- `plaintext = ciphertext XOR keystream`

---

## Script solver

```python
import struct, subprocess, sys

b = open('program.bin','rb').read()
assert len(b)==148 and b[:4]==b'BLV5'
a = struct.unpack('<72H', b[4:])
M = [[a[8*i+j] % 257 for j in range(8)] for i in range(8)]
t = [a[64+i] % 257 for i in range(8)]

P = 257
inv = lambda x: pow(x, P-2, P)

# eliminasi Gauss mod 257 (augmented)
A = [row[:] + [t[i]] for i, row in enumerate(M)]
n = 8
for c in range(n):
    piv = next(r for r in range(c, n) if A[r][c] % P)
    A[c], A[piv] = A[piv], A[c]
    iv = inv(A[c][c] % P)
    A[c] = [(x*iv) % P for x in A[c]]
    for r in range(n):
        if r != c and A[r][c] % P:
            f = A[r][c] % P
            A[r] = [(A[r][k] - f*A[c][k]) % P for k in range(n+1)]
v = [A[i][n] % P for i in range(n)]

# balik v[j] = (s[j]*197 + 31) & 255
inv197 = pow(197, -1, 256)  # = 109
s = bytes(((vj - 31) * inv197) % 256 for vj in v)
print("serial =", s.decode())          # YLpaZdJg

# buka vault
out = subprocess.run([sys.executable, 'runtime.py', s.decode()],
                     capture_output=True, text=True)
print(out.stdout.strip())               # CF2{...}
```

Output:

```
serial = YLpaZdJg
CF2{rev_gereja_blenduk_de2fe1fb3466b18bfaaa}
```

---

## Takeaway

Begitu sadar bahwa pemeriksaan bukan cek byte-per-byte melainkan **perkalian matriks atas field prima** (`M·v ≡ t mod 257`), soal runtuh jadi sekadar aljabar linear 8×8 — solve, lalu balik transformasi affine `mod 256` yang invertibel. Tidak ada ruang kunci 2⁶⁴ yang perlu di-brute. Modulus prima + transformasi koprima terhadap modulusnya adalah sinyal bahwa jalur yang dimaksud adalah *invert*, bukan *search*.
