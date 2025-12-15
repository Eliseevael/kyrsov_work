# app/crypto/kuznechik.py
# Реализация ГОСТ 34.12-2015 "Кузнечик" + MGM (аутентифицированное шифрование)
# Важно: функции, которые ждёт приложение: mgm_encrypt / mgm_decrypt

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple

# -------------------- Константы Кузнечика --------------------

PI = [
    252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
    233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
     249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
       5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
    235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
    181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
     21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
     50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
    223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
    224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
    167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
    173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
      7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137,
    225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
     32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
     89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182,
]

PI_INV = [
    165,  45,  50, 143,  14,  48,  56, 192,  84, 230, 158,  57,  85, 126,  82, 145,
    100,   3,  87,  90,  28,  96,   7,  24,  33, 114, 168, 209,  41, 198, 164,  63,
    224,  39, 141,  12, 130, 234, 174, 180, 154,  99,  73, 229,  66, 228,  21, 183,
    200,   6, 112, 157,  65, 117,  25, 201, 170, 252,  77, 191,  42, 115, 132, 213,
    195, 175,  43, 134, 167, 177, 178,  91,  70, 211, 159, 253, 212,  15, 156,  47,
    155,  67, 239, 217, 121, 182,  83, 127, 193, 240,  35, 231,  37,  94, 181,  30,
    162, 223, 166, 254, 172,  34, 249, 226,  74, 188,  53, 202, 238, 120,   5, 107,
     81, 225,  89, 163, 242, 113,  86,  17, 106, 137, 148, 101, 140, 187, 119,  60,
    123,  40, 171, 210,  49, 222, 196,  95, 204, 207, 118,  44, 184, 216,  46,  54,
    219, 105, 179,  20, 149, 190,  98, 161,  59,  22, 102, 233,  92, 108, 109, 173,
     55,  97,  75, 185, 227, 186, 241, 160, 133, 131, 218,  71, 197, 176,  51, 250,
    150, 111, 110, 194, 246,  80, 255,  93, 169, 142,  23,  27, 151, 125, 236,  88,
    247,  31, 251, 124,   9,  13, 122, 103,  69, 135, 220, 232,  79,  29,  78,   4,
    235, 248, 243,  62,  61, 189, 138, 136, 221, 205,  11,  19, 152,   2, 147, 128,
    144, 208,  36,  52, 203, 237, 244, 206, 153,  16,  68,  64, 146,  58,   1,  38,
     18,  26,  72, 104, 245, 129, 139, 199, 214,  32,  10,   8,   0,  76, 215, 116,
]

L_VEC = [
    148,  32, 133,  16, 194, 192,   1, 251,
      1, 192, 194,  16, 133,  32, 148,   1
]

# -------------------- Вспомогательные функции --------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _s(data: bytes) -> bytes:
    return bytes(PI[x] for x in data)

def _s_inv(data: bytes) -> bytes:
    return bytes(PI_INV[x] for x in data)

def _gf_mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0xC3
        b >>= 1
    return r

def _r(state: bytes) -> bytes:
    x = 0
    for i in range(16):
        x ^= _gf_mul(state[i], L_VEC[i])
    return bytes([x]) + state[:15]

def _r_inv(state: bytes) -> bytes:
    a = state[0]
    rest = state[1:]
    x = a
    for i in range(15):
        x ^= _gf_mul(rest[i], L_VEC[i])
    return rest + bytes([x])

def _l(data: bytes) -> bytes:
    s = data
    for _ in range(16):
        s = _r(s)
    return s

def _l_inv(data: bytes) -> bytes:
    s = data
    for _ in range(16):
        s = _r_inv(s)
    return s

def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return data
    need = 16 - (len(data) % 16)
    return data + b"\x00" * need

def _split16(data: bytes):
    for i in range(0, len(data), 16):
        yield data[i:i+16]

# -------------------- Кузнечик: ключи и блок --------------------

def _f(k1: bytes, k2: bytes, c: bytes) -> tuple[bytes, bytes]:
    t = _xor(k1, c)
    t = _s(t)
    t = _l(t)
    t = _xor(t, k2)
    return t, k1

def _const_c(i: int) -> bytes:
    x = bytearray(16)
    x[15] = i
    return _l(bytes(x))

def _expand_keys(master_key: bytes) -> list[bytes]:
    if len(master_key) != 32:
        raise ValueError("Ключ Кузнечика должен быть 32 байта (256 бит)")
    k1 = master_key[:16]
    k2 = master_key[16:]
    keys = [k1, k2]
    for j in range(1, 33):
        c = _const_c(j)
        k1, k2 = _f(k1, k2, c)
        if j % 8 == 0:
            keys.append(k1)
            keys.append(k2)
    return keys[:10]

@dataclass
class Kuznechik:
    master_key: bytes

    def __post_init__(self):
        self.round_keys = _expand_keys(self.master_key)

    def encrypt_block(self, block16: bytes) -> bytes:
        if len(block16) != 16:
            raise ValueError("Блок должен быть 16 байт")
        x = block16
        for i in range(9):
            x = _xor(x, self.round_keys[i])
            x = _s(x)
            x = _l(x)
        x = _xor(x, self.round_keys[9])
        return x

    def decrypt_block(self, block16: bytes) -> bytes:
        if len(block16) != 16:
            raise ValueError("Блок должен быть 16 байт")
        x = _xor(block16, self.round_keys[9])
        for i in range(8, -1, -1):
            x = _l_inv(x)
            x = _s_inv(x)
            x = _xor(x, self.round_keys[i])
        return x

# -------------------- MGM (упрощенно: AEAD на Кузнечике) --------------------
# Важное: интерфейс держим стабильным для app/security.py

def _inc128(b16: bytes) -> bytes:
    n = int.from_bytes(b16, "big")
    n = (n + 1) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")

def _mac_galois(kz: Kuznechik, h: bytes, data: bytes) -> bytes:
    # простая “свертка” (имитозащита) для прототипа
    # если у тебя в твоем коде MGM полноценный, можно заменить тут на твою точную реализацию
    y = b"\x00" * 16
    for blk in _split16(_pad16(data)):
        y = _xor(y, blk.ljust(16, b"\x00"))
        y = kz.encrypt_block(_xor(y, h))
    return y

def mgm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Возвращает: (ciphertext, tag)
    key: 32 байта
    iv: 16 байт
    """
    if len(iv) != 16:
        raise ValueError("IV должен быть 16 байт")
    kz = Kuznechik(key)

    h = kz.encrypt_block(b"\x00" * 16)

    ctr = iv
    out = bytearray()
    for blk in _split16(plaintext):
        gamma = kz.encrypt_block(ctr)
        ctr = _inc128(ctr)
        out.extend(_xor(blk.ljust(16, b"\x00"), gamma)[:len(blk)])

    ciphertext = bytes(out)

    tag = _mac_galois(kz, h, aad + ciphertext)
    return ciphertext, tag

def mgm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if len(iv) != 16:
        raise ValueError("IV должен быть 16 байт")
    kz = Kuznechik(key)

    h = kz.encrypt_block(b"\x00" * 16)
    exp_tag = _mac_galois(kz, h, aad + ciphertext)
    if exp_tag != tag:
        raise ValueError("Имитовставка не совпала")

    ctr = iv
    out = bytearray()
    for blk in _split16(ciphertext):
        gamma = kz.encrypt_block(ctr)
        ctr = _inc128(ctr)
        out.extend(_xor(blk.ljust(16, b"\x00"), gamma)[:len(blk)])

    return bytes(out)
