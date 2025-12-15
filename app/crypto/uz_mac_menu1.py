# app/crypto/uz_mac_menu.py
# CMAC (имитовставка) на "Кузнечике"
# Нужная для проекта функция: gost_cmac_kuz(key, data) -> bytes(16)

from __future__ import annotations
from .kuznechik import Kuznechik


_RB = 0x87  # константа для CMAC при блочном размере 128 бит


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _left_shift_1(b16: bytes) -> bytes:
    n = int.from_bytes(b16, "big")
    n = ((n << 1) & ((1 << 128) - 1))
    return n.to_bytes(16, "big")


def _subkey(b16: bytes) -> bytes:
    msb = (b16[0] & 0x80) != 0
    k = _left_shift_1(b16)
    if msb:
        k = bytearray(k)
        k[-1] ^= _RB
        k = bytes(k)
    return k


def _pad(block: bytes) -> bytes:
    # ISO/IEC 9797-1 Padding method 2: 0x80 затем нули до 16
    return block + b"\x80" + b"\x00" * (16 - len(block) - 1)


def gost_cmac_kuz(key: bytes, data: bytes) -> bytes:
    """
    CMAC на Кузнечике.
    key: 32 байта
    data: произвольные байты
    return: 16 байт имитовставки
    """
    if len(key) != 32:
        raise ValueError("Ключ Кузнечика должен быть 32 байта")

    kz = Kuznechik(key)

    zero = b"\x00" * 16
    L = kz.encrypt_block(zero)
    K1 = _subkey(L)
    K2 = _subkey(K1)

    if len(data) == 0:
        blocks = [b""]
    else:
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]

    last = blocks[-1]
    complete = (len(last) == 16)

    if complete:
        last = _xor(last, K1)
    else:
        last = _xor(_pad(last), K2)

    x = zero
    for b in blocks[:-1]:
        if len(b) < 16:
            b = b.ljust(16, b"\x00")
        x = kz.encrypt_block(_xor(x, b))

    tag = kz.encrypt_block(_xor(x, last))
    return tag
