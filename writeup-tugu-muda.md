# Tugu Muda — Writeup

**Kategori:** Forensics / Steganography
**Poin:** 380 (awal 500, min 250)
**Flag:** `CF2{for_tugu_muda_42751a1dca393b5ac5ce}`

---

## Deskripsi Soal

> Sebuah ekspor arsip terjadi pada 12 Oktober 2026 pukul 00.04 WIB. Korelasikan jejak kamera dan pergantian sandi radio untuk memulihkan muatan yang keasliannya dapat diverifikasi.

Lampiran: `for-tugu-muda-lampiran.zip`

## Isi Lampiran

```
format-ekspor.txt
camera-events.csv
radio-shifts.csv
kamera-41.png   (128x128 RGB)
kamera-42.png   (128x128 RGB)
kamera-43.png   (128x128 RGB)
```

### `format-ekspor.txt`

```
Spesifikasi ekspor kamera TM3 (bukan petunjuk lokasi bukti):
Kunci = SHA256(UTF8(phrase + "|" + nonce)). Interval sandi radio [mulai, akhir).
Kandidat pixel (x+2*y)%5==0, koordinat origin kiri atas, indeks y*width+x.
Acak list kandidat raster memakai Python 3 random.Random(int.from_bytes(SHA256(UTF8(nonce)).digest(), "big")).shuffle.
Baca LSB kanal B sesuai list; bit MSB-first per byte.
Frame: ASCII TM3, panjang ciphertext uint16 big-endian, ciphertext, HMAC-SHA256(key,ciphertext)[:16].
Ciphertext = zlib(payload) XOR blok SHA256(key || counter_uint32_be), counter mulai 0.
```

### `camera-events.csv`

```
event,utc,camera,nonce
motion,2026-10-11T16:57:00Z,kamera-41.png,TM-7321
export,2026-10-11T17:04:00Z,kamera-42.png,TM-7419
export,2026-10-11T17:26:00Z,kamera-43.png,TM-7420
```

### `radio-shifts.csv`

```
valid_from_WIB,valid_until_WIB,phrase
2026-10-11T23:00:00+07:00,2026-10-12T00:00:00+07:00,menara-membaca-angin
2026-10-12T00:00:00+07:00,2026-10-12T00:15:00+07:00,lentera-menjaga-arah
2026-10-12T00:15:00+07:00,2026-10-12T01:00:00+07:00,gerbang-menjaga-jejak
```

## Analisis

### 1. Korelasi waktu → kamera & nonce

Waktu ekspor di soal memakai **WIB (UTC+7)**, sedangkan log kamera memakai **UTC**:

```
2026-10-12 00:04 WIB  =  2026-10-11 17:04 UTC
```

Baris yang cocok di `camera-events.csv`:

| event  | utc                  | camera          | nonce   |
|--------|----------------------|-----------------|---------|
| export | 2026-10-11T17:04:00Z | `kamera-42.png` | `TM-7419` |

Dua baris lainnya pengecoh: `kamera-41` hanya event `motion` (16.57Z), dan `kamera-43` adalah ekspor lain pada 17.26Z (00.26 WIB).

### 2. Korelasi waktu → sandi radio

Interval sandi bersifat setengah terbuka `[mulai, akhir)`. Pukul 00.04 WIB tanggal 12 Oktober jatuh di:

```
[2026-10-12T00:00+07:00, 2026-10-12T00:15+07:00)  →  lentera-menjaga-arah
```

> **Jebakan:** jika tanggal UTC (11 Oktober) dibaca seolah WIB, atau zona waktu tidak dikonversi, yang terpilih adalah `menara-membaca-angin`. Kalau batas interval dianggap inklusif di sisi akhir dan waktunya tepat di batas, bisa juga salah pilih.

### 3. Turunkan kunci

```
key = SHA256("lentera-menjaga-arah|TM-7419")
```

### 4. Ekstraksi bit (LSB kanal Biru)

1. Kumpulkan semua indeks piksel `i = y*width + x` yang memenuhi `(x + 2*y) % 5 == 0`, dalam urutan raster (baris demi baris, kiri ke kanan).
2. Acak list tersebut dengan PRNG Python yang di-seed dari nonce:
   ```python
   seed = int.from_bytes(sha256(b"TM-7419").digest(), "big")
   random.Random(seed).shuffle(candidates)
   ```
3. Untuk setiap indeks dalam urutan teracak, ambil `B & 1`.
4. Susun bit menjadi byte, **MSB-first**.

### 5. Parsing frame TM3

```
| "TM3" (3B) | len (uint16 BE) | ciphertext (len B) | HMAC-SHA256(key, ct)[:16] |
```

Hasil pada `kamera-42.png` dengan nonce `TM-7419` langsung diawali magic `TM3`, menandakan urutan piksel (nonce) benar.

### 6. Verifikasi & dekripsi

- Hitung `HMAC-SHA256(key, ciphertext)[:16]` dan bandingkan dengan tag di frame. **Cocok**, jadi muatan terbukti autentik.
- Keystream: `SHA256(key || 0x00000000) || SHA256(key || 0x00000001) || ...`
- `plaintext = ciphertext XOR keystream`, lalu `zlib.decompress(plaintext)`.

### Validasi silang

| Kamera | Nonce | Header | Sandi | HMAC |
|---|---|---|---|---|
| kamera-41 | TM-7321 | ✗ (bukan `TM3`) | – | – |
| **kamera-42** | **TM-7419** | ✓ `TM3` | menara-membaca-angin | ✗ |
| **kamera-42** | **TM-7419** | ✓ `TM3` | **lentera-menjaga-arah** | **✓** |
| **kamera-42** | **TM-7419** | ✓ `TM3` | gerbang-menjaga-jejak | ✗ |
| kamera-43 | TM-7420 | ✗ (bukan `TM3`) | – | – |

Hanya satu kombinasi yang lolos HMAC, sesuai hasil korelasi waktu.

## Solver

```python
import sys, hashlib, hmac, random, zlib
from PIL import Image

IMG    = "kamera-42.png"
NONCE  = "TM-7419"
PHRASE = "lentera-menjaga-arah"

def extract(path, nonce):
    im = Image.open(path).convert("RGB")
    w, h = im.size
    px = im.load()
    cand = [y*w + x for y in range(h) for x in range(w) if (x + 2*y) % 5 == 0]
    seed = int.from_bytes(hashlib.sha256(nonce.encode()).digest(), "big")
    random.Random(seed).shuffle(cand)
    bits = [px[i % w, i // w][2] & 1 for i in cand]
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for b in bits[i:i+8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

raw = extract(IMG, NONCE)
assert raw[:3] == b"TM3", "magic tidak cocok"
L   = int.from_bytes(raw[3:5], "big")
ct  = raw[5:5+L]
tag = raw[5+L:5+L+16]

key = hashlib.sha256(f"{PHRASE}|{NONCE}".encode()).digest()
assert hmac.compare_digest(hmac.new(key, ct, hashlib.sha256).digest()[:16], tag), "HMAC gagal"

ks = b"".join(hashlib.sha256(key + i.to_bytes(4, "big")).digest() for i in range(L // 32 + 1))
pt = bytes(a ^ b for a, b in zip(ct, ks))
print(zlib.decompress(pt).decode())
```

Output:

```
CF2{for_tugu_muda_42751a1dca393b5ac5ce}
```

## Flag

```
CF2{for_tugu_muda_42751a1dca393b5ac5ce}
```

## Pelajaran

- Selalu samakan zona waktu sebelum mengorelasikan log (WIB ↔ UTC), apalagi kalau konversinya melewati pergantian tanggal.
- Perhatikan semantik interval `[mulai, akhir)`.
- Spesifikasi yang menyertakan MAC memberi oracle gratis: pakai HMAC untuk membuktikan kombinasi kunci yang benar, jangan cuma mengandalkan output yang "kelihatan masuk akal".
