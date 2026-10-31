# Tanjung Mas — Writeup

| | |
|---|---|
| **Kategori** | Reverse Engineering |
| **Poin** | 285 (awal 300, min 150) |
| **Lampiran** | `rev-tanjung-mas-lampiran.zip` (`manifest`, `README.txt`) |
| **Flag** | `CF2{rev_tanjung_mas_7d666448bc5641697c86}` |

## Deskripsi Soal

> Validator manifes memakai transformasi blok dengan dependensi antarbagian serial. Temukan satu serial delapan karakter yang membuka dokumen. Mengubah percabangan penolakan saja belum menjamin dokumen dapat dibaca.

`README.txt`:

> ELF x86-64 Linux, glibc. Jalankan `./manifest SERIAL8`. Analisis statis cukup dan diperbolehkan; tidak memerlukan jaringan atau hak admin.

## Recon

```
$ file manifest
manifest: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

String yang terlihat cuma `usage: manifest SERIAL8` dan `serial rejected`. Tidak ada flag dalam bentuk plaintext, jadi dokumennya pasti dienkripsi. Binarinya kecil (± 14 KB) dan seluruh logikanya ada di `main` (`0x1189`), jadi cukup dibaca dengan `objdump -d -M intel`.

## Analisis

### 1. Cek panjang & pembacaan serial

```asm
cmp    edi,0x2              ; argc == 2
call   strlen
cmp    rax,0x8              ; strlen(argv[1]) == 8
...
movzx  edi,BYTE PTR [rbx+rax*1]      ; s[i]   -> L
shl    edi,cl / or esi,edi
movzx  edi,BYTE PTR [rbx+rax*1+0x4]  ; s[i+4] -> R
shl    edi,cl / or edx,edi
```

Serial dipecah jadi dua word 32-bit little-endian:
- `L = s[0..3]`
- `R = s[4..7]`

### 2. Transformasi blok: Feistel 16 ronde

Kunci ronde ada di `.rodata` mulai `0x2080`, 16 × `uint32` (`0x2080`–`0x20bf`).

```asm
1210: mov  eax,edx          ; eax = R
      xor  eax,[rcx]        ; eax = R ^ k
      rol  eax,5
      mov  edi,edx
      rol  edi,13           ; edi = rol(R,13)
      add  eax,edi
      mov  edi,edx          ; edi = R (lama)
      xor  eax,esi          ; eax ^= L
      mov  edx,eax          ; R baru
      mov  esi,edi          ; L baru = R lama
```

Dalam pseudo-code:

```c
f(r, k) = rol(r ^ k, 5) + rol(r, 13);
for (i = 0; i < 16; i++) {
    tmp = L ^ f(R, K[i]);
    L = R;
    R = tmp;
}
if (L != 0xbdae4507 || R != 0x781b2a2c) puts("serial rejected");
```

Inilah "dependensi antarbagian serial" di deskripsi soal: tiap ronde, satu separuh serial dicampur ke separuh lainnya.

### 3. Dekripsi dokumen (alasan patch saja tidak cukup)

Kalau serial lolos, program **tidak** mencetak string statis:

```asm
movabs rbx,0xcbf29ce484222325   ; FNV-1a offset basis
movabs rsi,0x100000001b3        ; FNV prime
; h = FNV1a_64(serial)
...
movabs r14,0x9e3779b97f4a7c15   ; konstanta splitmix64
movabs r13,0xbf58476d1ce4e5b9
movabs r12,0x94d049bb133111eb
; untuk 41 byte ciphertext di 0x2040:
;   h += 0x9e37...; z = mix(h); putc((z & 0xff) ^ ct[i])
```

Keystream-nya diturunkan dari hash FNV-1a serial yang di-seed ke splitmix64. Jadi kalau kita cuma mem-patch `jne` penolakan, program memang akan mencoba mencetak "dokumen", tapi hasilnya sampah. Kita butuh serial yang **benar**.

## Solusi

Feistel selalu bisa dibalik tanpa perlu membalik fungsi `f`. Dari state akhir `(L', R')`:

```
R = L'
L = R' ^ f(L', k)
```

Jalankan mundur dari `K[15]` sampai `K[0]`, mulai dari target `(0xbdae4507, 0x781b2a2c)`, lalu pack kembali jadi 8 byte.

### Solver

```python
import struct

data = open('manifest', 'rb').read()
K  = struct.unpack('<16I', data[0x2080:0x20c0])   # kunci ronde
ct = data[0x2040:0x2069]                          # 41 byte dokumen terenkripsi

M = 0xffffffff
M64 = 2**64 - 1
rol = lambda x, n: ((x << n) | (x >> (32 - n))) & M
f   = lambda r, k: (rol(r ^ k, 5) + rol(r, 13)) & M

# Balik Feistel
L, R = 0xbdae4507, 0x781b2a2c
for k in reversed(K):
    L, R = R ^ f(L, k), L
serial = struct.pack('<II', L, R)
print('serial:', serial.decode())

# Dekripsi dokumen: FNV-1a 64 -> splitmix64
h = 0xcbf29ce484222325
for b in serial:
    h = ((h ^ b) * 0x100000001b3) & M64

out = bytearray()
for c in ct:
    h = (h + 0x9e3779b97f4a7c15) & M64
    z = h
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M64
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M64
    z ^= z >> 31
    out.append((z & 0xff) ^ c)
print('flag  :', out.decode())
```

Output:

```
serial: SKcnbmGE
flag  : CF2{rev_tanjung_mas_7d666448bc5641697c86}
```

### Verifikasi

```
$ ./manifest SKcnbmGE
CF2{rev_tanjung_mas_7d666448bc5641697c86}
```

## Flag

```
CF2{rev_tanjung_mas_7d666448bc5641697c86}
```

## Pelajaran

- Feistel bisa dibalik apa pun bentuk fungsi ronde `f`-nya. Dekripsi cukup dengan menjalankan ronde mundur, dan `f` tidak perlu diinvers.
- Kalau output yang berhasil diturunkan dari input (misalnya hash serial jadi seed keystream), patch percabangan tidak berguna dan input aslinya harus direkonstruksi.
- Konstanta "ajaib" langsung membuka identitas algoritmanya: `0xcbf29ce484222325`/`0x100000001b3` adalah FNV-1a, sedangkan `0x9e3779b97f4a7c15`/`0xbf58476d1ce4e5b9`/`0x94d049bb133111eb` adalah splitmix64.
