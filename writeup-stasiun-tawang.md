# Write-up CTF: Stasiun Tawang

**Nama soal:** Stasiun Tawang  
**Kategori:** Forensics / Network Forensics (DNS Exfiltration)  
**Poin:** 300  
**Lampiran:** `net-stasiun-tawang-lampiran.zip`  
**Status:** Solved

## Deskripsi soal

> Terminal TW-17 diduga mengirim arsip melalui resolver. Identifikasi lalu lintas terminal pada waktu insiden dan pulihkan objek lengkap, dengan menghindari retransmisi dan fragmen rusak.

## Flag

```text
CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```

## 1. Identifikasi isi lampiran

Berkas ZIP memuat tiga file:

```text
dhcp.csv
incident.txt
tawang.pcap
```

- `dhcp.csv`: riwayat alamat IP terminal yang berlaku pada rentang waktu tertentu.
- `incident.txt`: petunjuk waktu insiden, format query, dan proses encoding.
- `tawang.pcap`: tangkapan jaringan yang harus dianalisis.

Informasi penting dari `incident.txt`:

```text
Insiden 12 Oktober 2026 09.20 WIB.
Ring buffer PCAP memakai waktu sintetis, gunakan identitas sumber
dari DHCP pada waktu insiden.
Capture RAW/IPv4/UDP.
Format sinkronisasi: session.seq.chunk.crc32.sync.archive.invalid
CRC32 dihitung pada teks chunk ASCII.
Encoding objek mengikuti format arsip zlib standar setelah base32.
```

Artinya **jangan menggunakan timestamp PCAP untuk menentukan IP terminal**. Acuan waktu yang benar adalah waktu insiden pada `incident.txt`, kemudian dicocokkan dengan `dhcp.csv`.

## 2. Menentukan alamat IP terminal TW-17

Waktu insiden:

- **12 Oktober 2026, 09.20 WIB**
- Dalam UTC: **12 Oktober 2026, 02.20 UTC**

Isi `dhcp.csv`:

```csv
asset,ip,start_utc,end_utc
TW-17,192.0.2.61,2026-10-11T00:00Z,2026-10-12T00:00Z
TW-17,192.0.2.77,2026-10-12T00:00Z,2026-10-13T00:00Z
TW-23,192.0.2.88,2026-10-12T00:00Z,2026-10-13T00:00Z
```

Alamat IP TW-17 pada waktu insiden adalah **`192.0.2.77`**. Alamat `192.0.2.61` merupakan lease sebelumnya dan `192.0.2.88` milik terminal lain.

Filter yang relevan saat membuka PCAP di Wireshark:

```wireshark
ip.src == 192.0.2.77 && udp.dstport == 53 && dns
```

Sasarannya adalah query DNS dari terminal ke resolver **`192.0.2.53`**.

## 3. Memahami pola DNS exfiltration

Di antara trafik DNS biasa seperti `node63.status.invalid`, terdapat query dengan nama domain yang membawa data:

```text
b7e4.002.YS4PG5HDGMRWWOYERN.67886973.sync.archive.invalid
```

Susunan label:

```text
session . seq . chunk . crc32 . sync . archive . invalid
 b7e4   002   BASE32   67886973
```

- `session`: penanda sesi transfer; untuk TW-17 nilainya **`b7e4`**.
- `seq`: nomor urut fragmen (`000` hingga `004`).
- `chunk`: bagian data berformat Base32.
- `crc32`: checksum CRC32 atas **teks ASCII chunk**, bukan atas hasil decode.
- `sync.archive.invalid`: suffix penanda trafik arsip.

Hasil inspeksi file `tawang.pcap`:

| Keterangan | Jumlah |
|---|---:|
| Total paket PCAP | 219 |
| Query kandidat IP `192.0.2.77`, session `b7e4` | 13 |
| Paket dengan CRC32 benar (termasuk duplikat) | 8 |
| Paket dengan CRC32 salah | 5 |
| Retransmisi valid yang harus dibuang | 3 |
| Fragmen valid unik | **5** |

Contoh: nomor `002` muncul dalam beberapa variasi. Chunk `YS4PG5HDGMRWWOYERN` cocok dengan CRC `67886973`, sedangkan chunk yang dibalik (`NREYOWWRMGDH5GP4SY`) **tidak lolos verifikasi** terhadap CRC yang sama.

## 4. Validasi, deduplikasi, dan pengurutan

Langkah yang dilakukan:

1. Pilih hanya query dari IP sumber `192.0.2.77` menuju UDP port 53.
2. Ambil nama DNS yang berakhiran `.sync.archive.invalid`.
3. Pilih hanya session `b7e4`.
4. Verifikasi `zlib.crc32(chunk.encode("ascii")) & 0xffffffff` terhadap label CRC32.
5. Buang query yang gagal CRC32.
6. Jika terdapat `seq` yang sudah diproses dengan chunk identik, abaikan sebagai retransmisi.
7. Urutkan chunk berdasarkan sequence **secara numerik**.

Lima fragmen yang benar:

| Sequence | Chunk yang lolos CRC32 | CRC32 |
|---|---|---|
| `000` | `PCOHG5RTVLHEWLMJF4` | `01810e1a` |
| `001` | `XESLGOFTGYWL2JFRH4` | `67deebb8` |
| `002` | `YS4PG5HDGMRWWOYERN` | `67886973` |
| `003` | `KMJW3DAS2NWFEDGMNV` | `220ecab4` |
| `004` | `VACQA2FPB4QQ` | `399b9605` |

Setelah diurutkan dan digabungkan:

```text
PCOHG5RTVLHEWLMJF4XESLGOFTGYWL2JFRH4YS4PG5HDGMRWWOYERNKMJW3DAS2NWFEDGMNVVACQA2FPB4QQ
```

## 5. Decode Base32 dan dekompresi zlib

Gabungkan fragmen tanpa karakter pemisah. Lakukan decode Base32, dengan padding `=` bila dibutuhkan, kemudian dekompresi zlib.

```python
import base64
import zlib

encoded = (
    "PCOHG5RTVLHEWLMJF4"
    "XESLGOFTGYWL2JFRH4"
    "YS4PG5HDGMRWWOYERN"
    "KMJW3DAS2NWFEDGMNV"
    "VACQA2FPB4QQ"
)
compressed = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
print(zlib.decompress(compressed).decode())
```

Hasil:

```text
CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```

Data terkompresi hasil decode Base32 berukuran **52 byte**, dan hasil dekompresi berukuran **44 byte**.

## 6. Solver otomatis (Python, tanpa dependensi eksternal)

Simpan sebagai `solve.py`, kemudian jalankan dari folder yang berisi ZIP lampiran:

```bash
python3 solve.py 1792902624_net-stasiun-tawang-lampiran.zip
```

Solver membaca CSV dan PCAP langsung dari ZIP, menentukan IP dari lease DHCP, memilih sesi yang benar, memvalidasi CRC32, membuang retransmisi, lalu memulihkan objek.

```python
#!/usr/bin/env python3
# Stasiun Tawang - CTF solver
# Penggunaan: python3 solve.py 1792902624_net-stasiun-tawang-lampiran.zip

import base64
import csv
import io
import ipaddress
import re
import struct
import sys
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

INCIDENT = datetime(2026, 10, 12, 2, 20, tzinfo=timezone.utc)
ASSET = "TW-17"
SESSION = "b7e4"
SUFFIX = ".sync.archive.invalid"


def get_source_ip(dhcp_csv):
    rows = csv.DictReader(io.StringIO(dhcp_csv))
    for row in rows:
        start = datetime.fromisoformat(row["start_utc"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(row["end_utc"].replace("Z", "+00:00"))
        if row["asset"] == ASSET and start <= INCIDENT < end:
            return row["ip"]
    raise ValueError("Tidak ada lease DHCP untuk terminal pada waktu insiden")


def read_dns_queries(pcap_bytes):
    # PCAP little-endian, linktype RAW IPv4 (101).
    if pcap_bytes[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("PCAP bukan format little-endian yang didukung")
    linktype = struct.unpack_from("<I", pcap_bytes, 20)[0]
    if linktype != 101:
        raise ValueError(f"Linktype tidak sesuai (dapat {linktype}, perlu RAW=101)")

    pos = 24
    while pos + 16 <= len(pcap_bytes):
        _sec, _usec, captured, _original = struct.unpack_from("<IIII", pcap_bytes, pos)
        pos += 16
        packet = pcap_bytes[pos:pos + captured]
        pos += captured
        if len(packet) < 28 or (packet[0] >> 4) != 4:
            continue

        header_len = (packet[0] & 0x0F) * 4
        if packet[9] != 17 or len(packet) < header_len + 8 + 12:
            continue  # Bukan IPv4/UDP/DNS

        src = str(ipaddress.IPv4Address(packet[12:16]))
        dst_port = struct.unpack_from("!H", packet, header_len + 2)[0]
        if dst_port != 53:
            continue

        dns = packet[header_len + 8:]
        qdcount = struct.unpack_from("!H", dns, 4)[0]
        if qdcount != 1:
            continue

        labels = []
        idx = 12  # Lewati header DNS 12 byte
        while idx < len(dns):
            length = dns[idx]
            idx += 1
            if length == 0:
                break
            if length > 63 or idx + length > len(dns):
                labels = []
                break
            labels.append(dns[idx:idx + length].decode("ascii"))
            idx += length

        if labels:
            yield src, ".".join(labels)


def solve(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        source_ip = get_source_ip(archive.read("dhcp.csv").decode())
        pcap = archive.read("tawang.pcap")

    chunks = {}
    valid = bad_crc = retransmission = 0
    for src, qname in read_dns_queries(pcap):
        if src != source_ip or not qname.endswith(SUFFIX):
            continue
        labels = qname.split(".")
        if len(labels) != 7 or labels[0] != SESSION:
            continue

        _session, seq, chunk, crc, _sync, _archive, _invalid = labels
        if not re.fullmatch(r"\d{3}", seq) or not re.fullmatch(r"[0-9a-fA-F]{8}", crc):
            continue

        expected = int(crc, 16)
        actual = zlib.crc32(chunk.encode("ascii")) & 0xFFFFFFFF
        if actual != expected:
            bad_crc += 1
            continue

        valid += 1
        seq_num = int(seq)
        if seq_num in chunks:
            if chunks[seq_num] != chunk:
                raise ValueError(f"Konflik chunk valid pada sequence {seq}")
            retransmission += 1
            continue
        chunks[seq_num] = chunk

    if not chunks:
        raise ValueError("Tidak ada chunk valid")
    if sorted(chunks) != list(range(len(chunks))):
        raise ValueError("Sequence tidak lengkap/terputus")

    encoded = "".join(chunks[seq] for seq in sorted(chunks))
    compressed = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
    recovered = zlib.decompress(compressed)

    Path("recovered.zlib").write_bytes(compressed)
    Path("recovered.txt").write_bytes(recovered)

    print(f"IP terminal : {source_ip}")
    print(f"Session     : {SESSION}")
    print(f"CRC valid   : {valid}")
    print(f"CRC rusak   : {bad_crc}")
    print(f"Retransmisi : {retransmission}")
    print(f"Chunk unik  : {len(chunks)}")
    print(f"Zlib size   : {len(compressed)} bytes")
    print(f"FLAG        : {recovered.decode()}")


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else
          "1792902624_net-stasiun-tawang-lampiran.zip")
```

Contoh output:

```text
IP terminal : 192.0.2.77
Session     : b7e4
CRC valid   : 8
CRC rusak   : 5
Retransmisi : 3
Chunk unik  : 5
Zlib size   : 52 bytes
FLAG        : CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```

Solver juga menghasilkan `recovered.zlib` (arsip hasil rekonstruksi) dan `recovered.txt` (objek yang telah didekompresi).

## 7. Kesimpulan

Tantangan ini memadukan **korelasi DHCP dengan waktu insiden** dan **rekonstruksi data DNS**. Kesalahan umum adalah mengikuti timestamp sintetis PCAP, memilih IP lama, menggabungkan seluruh query tanpa memilah session, atau melakukan decode sebelum memverifikasi CRC32. Dengan validasi checksum, deduplikasi berdasarkan nomor urut, dan decode Base32 → zlib, objek berhasil dipulihkan secara lengkap.

**Flag akhir:**

```text
CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```
