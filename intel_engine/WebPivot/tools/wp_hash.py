"""wp_hash — MurmurHash3 + Shodan/FOFA favicon hash (stdlib-only)."""
import base64
import hashlib

def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-python MurmurHash3 x86_32, signed — matches mmh3.hash() (Shodan)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = ((data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) |
              ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)) & 0xffffffff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1

def shodan_favicon_hash(raw: bytes) -> int:
    """Shodan/FOFA favicon hash = mmh3 of MIME-base64(favicon bytes)."""
    return mmh3_x86_32(base64.encodebytes(raw))


__all__ = [_n for _n in dir() if not _n.startswith("__")]
