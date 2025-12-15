
from typing import Optional
from typing import Tuple, List
import os, sys, binascii, secrets

GF_POLY = 0xC3    # x^8 + x^7 + x^6 + x + 1
BLOCK   = 16      # 128 бит

# S-box Pi (RFC 7801, секция 4.1) 
PI = bytes((
    252,238,221, 17,207,110, 49, 22,251,196,250,218, 35,197,  4, 77,
    233,119,240,219,147, 46,153,186, 23, 54,241,187, 20,205, 95,193,
    249, 24,101, 90,226, 92,239, 33,129, 28, 60, 66,139,  1,142, 79,
      5,132,  2,174,227,106,143,160,  6, 11,237,152,127,212,211, 31,
    235, 52, 44, 81,234,200, 72,171,242, 42,104,162,253, 58,206,204,
    181,112, 14, 86,  8, 12,118, 18,191,114, 19, 71,156,183, 93,135,
     21,161,150, 41, 16,123,154,199,243,145,120,111,157,158,178,177,
     50,117, 25, 61,255, 53,138,126,109, 84,198,128,195,189, 13, 87,
    223,245, 36,169, 62,168, 67,201,215,121,214,246,124, 34,185,  3,
    224, 15,236,222,122,148,176,188,220,232, 40, 80, 78, 51, 10, 74,
    167,151, 96,115, 30,  0, 98, 68, 26,184, 56,130,100,159, 38, 65,
    173, 69, 70,146, 39, 94, 85, 47,140,163,165,125,105,213,149, 59,
      7, 88,179, 64,134,172, 29,247, 48, 55,107,228,136,217,231,137,
    225, 27,131, 73, 76, 63,248,254,141, 83,170,144,202,216,133, 97,
     32,113,103,164, 45, 43,  9, 91,203,155, 37,208,190,229,108, 82,
     89,166,116,210,230,244,180,192,209,102,175,194, 57, 75, 99,182
))
# Вектор коэффициентов L-преобразования (RFC 7801, 4.2) 
L_VEC = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

# ГЛОБАЛ: сохраняем «предыдущий MAC» 
LAST = None  # dict | None: {'mac': bytes, 'key': bytes, 's_bits': int, 'source': str, 'path': str|None, 'size': int|None}

# Базовые операции поля GF(2^8) 
def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= GF_POLY
        b >>= 1
    return res

def X(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def S(state: bytes) -> bytes:
    return bytes(PI[x] for x in state)

def R(state: bytes) -> bytes:
    # R(a15..a0) = l(a15..a0) || a15 || ... || a1
    acc = 0
    for i in range(16):
        acc ^= gf_mul(state[i], L_VEC[i])
    return bytes([acc]) + state[:15]

def L(state: bytes) -> bytes:
    s = state
    for _ in range(16):
        s = R(s)
    return s

def LSX(a: bytes, b: bytes) -> bytes:
    return L(S(X(a, b)))

#  Ключевое расписание Кузнечика 
def C_const(i: int) -> bytes:
    v = bytearray(16)
    v[15] = i & 0xFF
    return L(bytes(v))

def F(k1: bytes, k2: bytes, c: bytes) -> Tuple[bytes, bytes]:
    t = k1
    k1 = X(LSX(k1, c), k2)
    k2 = t
    return k1, k2

def expand_keys(master_key: bytes) -> List[bytes]:
    assert len(master_key) == 32
    k1, k2 = master_key[:16], master_key[16:]
    rks = [k1, k2]
    for j in range(4):
        for i in range(1, 9):
            c = C_const(8*j + i)
            k1, k2 = F(k1, k2, c)
        rks.extend([k1, k2])
    return rks  # 10 раундовых ключей

def kuz_encrypt_block(key32: bytes, block16: bytes) -> bytes:
    assert len(key32) == 32 and len(block16) == 16
    rks = expand_keys(key32)
    s = block16
    for i in range(9):
        s = LSX(s, rks[i])
    s = X(s, rks[9])
    return s
# CMAC (имитовставка) по ГОСТ 34.13-2018 
def left_shift_1(b: bytes) -> Tuple[bytes, int]:
    x = int.from_bytes(b, 'big')
    carry = (x >> (BLOCK*8 - 1)) & 1
    x = ((x << 1) & ((1 << (BLOCK*8)) - 1))
    return x.to_bytes(BLOCK, 'big'), carry

def gen_subkeys(key: bytes) -> Tuple[bytes, bytes]:
    Rb = 0x87  # B128
    Rv = kuz_encrypt_block(key, b'\x00' * BLOCK)
    K1, c1 = left_shift_1(Rv)
    if c1 == 1:
        K1 = (int.from_bytes(K1, 'big') ^ Rb).to_bytes(BLOCK, 'big')
    K2, c2 = left_shift_1(K1)
    if c2 == 1:
        K2 = (int.from_bytes(K2, 'big') ^ Rb).to_bytes(BLOCK, 'big')
    return K1, K2

def pad_proc3(last: bytes) -> bytes:
    return last + b'\x80' + b'\x00' * (BLOCK - len(last) - 1)

def gost_cmac_kuz(key: bytes, data: bytes, s_bits: int = 64) -> bytes:
    assert 0 < s_bits <= 128 and len(key) == 32
    K1, K2 = gen_subkeys(key)
    q, r = divmod(len(data), BLOCK)
    blocks = [data[i*BLOCK:(i+1)*BLOCK] for i in range(q)]

    if r == 0 and len(data) != 0:
        last = blocks[-1]
        blocks = blocks[:-1]
        Mq = X(last, K1)
    else:
        last = data[q*BLOCK:]
        last_padded = pad_proc3(last)
        Mq = X(last_padded, K2)

    Xv = b'\x00' * BLOCK
    for P in blocks:
        Xv = kuz_encrypt_block(key, X(Xv, P))
    T_full = kuz_encrypt_block(key, X(Xv, Mq))

    s_bytes = (s_bits + 7) // 8
    mac = T_full[:s_bytes]
    if s_bits % 8:
        mask = 0xFF & (0xFF << (8 - (s_bits % 8)))
        mac = mac[:-1] + bytes([mac[-1] & mask])
    return mac

#  Вспомогательные штуки меню 
def hexstr(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def read_key_interactive() -> bytes:
    print("\nВведите ключ (64 hex символа = 32 байта).")
    print("Можно оставить пусто — тогда сгенерируем случайный ключ.")
    while True:
        s = input("Ключ (hex) [пусто=сгенерировать]: ").strip().lower()
        if s == "":
            key = secrets.token_bytes(32)
            print(f"Сгенерированный ключ: {hexstr(key)}")
            return key
        try:
            key = bytes.fromhex(s)
        except Exception:
            print("✗ Ошибка: это не похоже на hex. Повторите.")
            continue
        if len(key) != 32:
            print(f"✗ Ошибка: длина ключа {len(key)} байт, нужна 32. Повторите.")
            continue
        return key

def read_s_bits() -> int:
    while True:
        s = input("Длина имитовставки s (в битах, 1..128) [по умолчанию 64]: ").strip()
        if s == "":
            return 64
        if not s.isdigit():
            print("✗ Введите число от 1 до 128.")
            continue
        s_bits = int(s)
        if 1 <= s_bits <= 128:
            return s_bits
        print("✗ Допустимый диапазон 1..128.")

# ---------- Служебное: сохранить «предыдущий MAC» ----------
def save_last(mac: bytes, key: bytes, s_bits: int, source: str, path: Optional[str], size: Optional[int]):
    global LAST
    LAST = {
        "mac": mac,
        "key": key,
        "s_bits": s_bits,
        "source": source,  # 'file' | 'hex'
        "path": path,
        "size": size,
    }

#  Действия 
def action_selftest():
    print("\n— Самопроверка на эталонных примерах —")
    key_hex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
    pt_hex  = "1122334455667700ffeeddccbbaa9988"
    exp_ct  = "7f679d90bebc24305a468d42b9d4edcd"
    key = bytes.fromhex(key_hex)
    pt  = bytes.fromhex(pt_hex)
    ct  = kuz_encrypt_block(key, pt)
    print(f"[SELFTEST] E_K(P) = {hexstr(ct)} ; ожидается = {exp_ct} ; OK={hexstr(ct)==exp_ct}")

    P = (
        "1122334455667700ffeeddccbbaa9988"
        "00112233445566778899aabbcceeff0a"
        "112233445566778899aabbcceeff0a00"
        "2233445566778899aabbcceeff0a0011"
    )
    mac = gost_cmac_kuz(key, bytes.fromhex(P), s_bits=64)
    exp_mac = "336f4d296059fbe3"
    print(f"[SELFTEST] MAC     = {hexstr(mac)} ; ожидается = {exp_mac} ; OK={hexstr(mac)==exp_mac}")
    print()

def action_mac_file():
    print("\n— Вычисление имитовставки для ФАЙЛА —")
    key = read_key_interactive()
    s_bits = read_s_bits()
    path = input("Путь к файлу: ").strip()
    if not os.path.exists(path) or not os.path.isfile(path):
        print("✗ Файл не найден.")
        return
    with open(path, "rb") as f:
        data = f.read()
    mac = gost_cmac_kuz(key, data, s_bits=s_bits)
    print("\nИтоги:")
    print(f"  Файл: {path}")
    print(f"  Размер: {len(data)} байт")
    print(f"  s (биты): {s_bits}")
    print(f"  Ключ: {hexstr(key)}")
    print(f"  MAC: {hexstr(mac)}")
    print("  → Сохранено как ПРЕДЫДУЩИЙ MAC для последующего сравнения.")
    print()
    save_last(mac, key, s_bits, source="file", path=path, size=len(data))

def action_mac_hex():
    print("\n— Вычисление имитовставки для HEX-строки —")
    key = read_key_interactive()
    s_bits = read_s_bits()
    while True:
        h = input("Данные (hex): ").strip().lower()
        try:
            data = bytes.fromhex(h)
            break
        except Exception:
            print("✗ Это не похоже на hex. Повторите.")
    mac = gost_cmac_kuz(key, data, s_bits=s_bits)
    print("\nИтоги:")
    print(f"  Длина данных: {len(data)} байт")
    print(f"  s (биты): {s_bits}")
    print(f"  Ключ: {hexstr(key)}")
    print(f"  MAC: {hexstr(mac)}")
    print("  → Сохранено как ПРЕДЫДУЩИЙ MAC для последующего сравнения.")
    print()
    save_last(mac, key, s_bits, source="hex", path=None, size=len(data))

def action_compare_with_last():
    global LAST
    print("\n— Сверить с ПРЕДЫДУЩИМ MAC —")
    if LAST is None:
        print("✗ Пока нет сохранённого «предыдущего MAC». Сначала посчитай MAC (пункты 2 или 3).")
        print()
        return

    # Используем те же key и s_bits, что и у «предыдущего»
    key = LAST["key"]
    s_bits = LAST["s_bits"]
    print(f"Используем сохранённые параметры: s={s_bits} бит, ключ={hexstr(key)}")
    print("Выбери источник текущих данных для сравнения:")
    print("  1) Файл")
    print("  2) Hex-строка")
    choice = input("Ваш выбор [1-2]: ").strip()

    if choice == "1":
        path = input("Путь к файлу: ").strip()
        if not os.path.exists(path) or not os.path.isfile(path):
            print("✗ Файл не найден.\n")
            return
        data = open(path, "rb").read()
        mac_now = gost_cmac_kuz(key, data, s_bits=s_bits)
        src_now = f"file:{path}"
        size_now = len(data)
    elif choice == "2":
        while True:
            h = input("Данные (hex): ").strip().lower()
            try:
                data = bytes.fromhex(h)
                break
            except Exception:
                print("✗ Это не похоже на hex. Повторите.")
        mac_now = gost_cmac_kuz(key, data, s_bits=s_bits)
        src_now = "hex:<введено>"
        size_now = len(data)
    else:
        print("✗ Неверный выбор.\n")
        return

    mac_prev_hex = hexstr(LAST["mac"])
    mac_now_hex  = hexstr(mac_now)

    print("\nСРАВНЕНИЕ:")
    print(f"  ПРЕДЫДУЩИЙ: src={LAST['source']}{(':'+LAST['path']) if LAST['path'] else ''}  size={LAST['size']}  MAC={mac_prev_hex}")
    print(f"  ТЕКУЩИЙ:    src={src_now}  size={size_now}  MAC={mac_now_hex}")
    print("  СОВПАДЕНИЕ:", "ДА" if mac_now == LAST["mac"] else "НЕТ")
    print()

    # Обновим «предыдущий» на текущий — удобно для цепочки сравнений
    save_last(mac_now, key, s_bits, source=("file" if choice=="1" else "hex"),
              path=(path if choice=="1" else None), size=size_now)

def main_menu():
    while True:
        print("1) Самопроверка (ГОСТ-эталоны)")
        print("2) Вычислить MAC для файла")
        print("3) Вычислить MAC для hex-строки")
        print("4) Сверить с ПРЕДЫДУЩИМ MAC")
        print("5) Выход")
        choice = input("Выберите пункт [1-5]: ").strip()
        if choice == "1":
            action_selftest()
        elif choice == "2":
            action_mac_file()
        elif choice == "3":
            action_mac_hex()
        elif choice == "4":
            action_compare_with_last()
        elif choice == "5":
            print("Готово. До связи!")
            return
        else:
            print("✗ Неверный пункт меню.\n")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[Прервано пользователем]")

