import os, binascii, secrets
from typing import Tuple

# --- Константы ---
BLOCK = 16  # 128 бит

# --- S-box Pi (ГОСТ) ---
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

L_VEC = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

# --- Базовые операции ---
def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0xC3
        b >>= 1
    return res

def X(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def S(state: bytes) -> bytes:
    return bytes(PI[x] for x in state)

def R(state: bytes) -> bytes:
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

# --- Шифр Кузнечик ---
def expand_keys(master_key: bytes) -> list:
    k1, k2 = master_key[:16], master_key[16:]
    keys = [k1, k2]
    for j in range(4):
        for i in range(1, 9):
            c = L(bytes([0] * 15 + [8*j + i]))
            k1, k2 = X(LSX(k1, c), k2), k1
        keys.extend([k1, k2])
    return keys

def kuz_encrypt_block(key: bytes, block: bytes) -> bytes:
    keys = expand_keys(key)
    s = block
    for i in range(9):
        s = LSX(s, keys[i])
    return X(s, keys[9])

# --- MGM режим ---
def mgm_inc_counter(counter: bytes) -> bytes:
    cnt = int.from_bytes(counter, 'big')
    return ((cnt + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, 'big')

def mgm_pad_data(data: bytes) -> bytes:
    if len(data) % BLOCK == 0:
        return data
    padded = data + b'\x80'
    while len(padded) % BLOCK != 0:
        padded += b'\x00'
    return padded

def mgm_ghash(key: bytes, data: bytes) -> bytes:
    H = kuz_encrypt_block(key, b'\x00' * BLOCK)
    blocks = [data[i:i+BLOCK] for i in range(0, len(data), BLOCK)]
    Y = b'\x00' * BLOCK
    for block in blocks:
        if len(block) < BLOCK:
            block = block + b'\x80' + b'\x00' * (BLOCK - len(block) - 1)
        Y = X(kuz_encrypt_block(key, X(Y, block)), H)
    return Y

def mgm_encrypt(key: bytes, iv: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
    IV_padded = iv + b'\x00\x00\x00\x01'
    J0 = iv + b'\x00\x00\x00\x02'
    
    # Шифрование
    counter = IV_padded
    ciphertext_blocks = []
    for i in range(0, len(plaintext), BLOCK):
        block = plaintext[i:i+BLOCK]
        keystream = kuz_encrypt_block(key, counter)
        ciphertext_blocks.append(X(block, keystream))
        counter = mgm_inc_counter(counter)
    ciphertext = b''.join(ciphertext_blocks)
    
    # Тег аутентификации
    A_hash = mgm_ghash(key, mgm_pad_data(associated_data))
    C_hash = mgm_ghash(key, mgm_pad_data(ciphertext))
    S = X(A_hash, C_hash)
    T_full = kuz_encrypt_block(key, J0)
    auth_tag = X(S, T_full)[:8]  # 64 бита
    
    return ciphertext, auth_tag

def mgm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, associated_data: bytes, auth_tag: bytes) -> Tuple[bytes, bool]:
    J0 = iv + b'\x00\x00\x00\x02'
    
    # Проверка тега
    A_hash = mgm_ghash(key, mgm_pad_data(associated_data))
    C_hash = mgm_ghash(key, mgm_pad_data(ciphertext))
    S = X(A_hash, C_hash)
    T_full = kuz_encrypt_block(key, J0)
    expected_tag = X(S, T_full)[:8]
    
    if expected_tag != auth_tag:
        return b'', False
    
    # Расшифрование
    IV_padded = iv + b'\x00\x00\x00\x01'
    counter = IV_padded
    plaintext_blocks = []
    for i in range(0, len(ciphertext), BLOCK):
        block = ciphertext[i:i+BLOCK]
        keystream = kuz_encrypt_block(key, counter)
        plaintext_blocks.append(X(block, keystream))
        counter = mgm_inc_counter(counter)
    
    return b''.join(plaintext_blocks), True

# --- Основные функции ---
def test_mgm():
    """Тест из ГОСТ 34.13-2018"""
    print("=== ТЕСТ ИЗ ГОСТ 34.13-2018 ===")
    
    key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv = bytes.fromhex("112233445566778899aabbcc")
    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    associated_data = bytes.fromhex("00112233445566778899aabbcceeff0a")
    
    print(f"Ключ: {binascii.hexlify(key).decode()}")
    print(f"IV: {binascii.hexlify(iv).decode()}")
    print(f"Открытый текст: {binascii.hexlify(plaintext).decode()}")
    print(f"Ассоциированные данные: {binascii.hexlify(associated_data).decode()}")
    
    # Шифрование
    ciphertext, tag = mgm_encrypt(key, iv, plaintext, associated_data)
    print(f"Шифртекст: {binascii.hexlify(ciphertext).decode()}")
    print(f"Тег: {binascii.hexlify(tag).decode()}")
    
    # Расшифрование
    decrypted, auth_ok = mgm_decrypt(key, iv, ciphertext, associated_data, tag)
    print(f"Расшифрованный: {binascii.hexlify(decrypted).decode()}")
    print(f"Аутентификация: {'УСПЕХ' if auth_ok else 'ОШИБКА'}")
    print(f"Совпадение: {'ДА' if decrypted == plaintext else 'НЕТ'}")
    
    # Проверка с измененными данными
    modified_ad = associated_data + b"\x00"
    _, auth_ok_modified = mgm_decrypt(key, iv, ciphertext, modified_ad, tag)
    print(f"С измененными данными: {'УСПЕХ' if auth_ok_modified else 'ОШИБКА'}")
    print()

def encrypt_file(file_path: str):
    """Шифрование файла с указанным путем"""
    print("=== ШИФРОВАНИЕ ФАЙЛА ===")
    
    if not os.path.exists(file_path):
        print(f"Ошибка: файл '{file_path}' не найден!")
        return
    
    # Используем тестовый ключ из ГОСТ
    key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    iv = secrets.token_bytes(12)
    
    # Ассоциированные данные
    associated_data = b"Student_Group_Lab_MGM"
    
    # Читаем и шифруем файл
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    ciphertext, tag = mgm_encrypt(key, iv, plaintext, associated_data)
    
    # Формируем пути для выходных файлов
    base_name = os.path.splitext(file_path)[0]
    enc_file = base_name + ".enc"
    tag_file = base_name + ".tag"
    iv_file = base_name + ".iv"
    
    # Сохраняем результаты
    with open(enc_file, "wb") as f:
        f.write(ciphertext)
    with open(tag_file, "wb") as f:
        f.write(tag)
    with open(iv_file, "wb") as f:
        f.write(iv)
    
    print(f"Файл '{file_path}' зашифрован")
    print(f"Размер: {len(plaintext)} байт")
    print(f"Тег: {binascii.hexlify(tag).decode()}")
    print(f"IV: {binascii.hexlify(iv).decode()}")
    print(f"Ассоциированные данные: {associated_data.decode()}")
    print(f"Зашифрованный файл: {enc_file}")
    print(f"Файл тега: {tag_file}")
    print(f"Файл IV: {iv_file}")
    print()

def test_integrity():
    """Проверка целостности при изменении ассоциированных данных"""
    print("=== ПРОВЕРКА ЦЕЛОСТНОСТИ ===")
    
    # Запрашиваем базовое имя файлов
    base_name = input("Введите путь к файлу без расширения (например, document): ").strip()
    
    enc_file = base_name + ".enc"
    tag_file = base_name + ".tag"
    iv_file = base_name + ".iv"
    
    if not all(os.path.exists(f) for f in [enc_file, tag_file, iv_file]):
        print("Ошибка: не все необходимые файлы найдены!")
        print("Убедитесь, что существуют файлы:")
        print(f"  {enc_file}")
        print(f"  {tag_file}")
        print(f"  {iv_file}")
        return
    
    key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    
    # Загружаем зашифрованные данные
    with open(enc_file, "rb") as f:
        ciphertext = f.read()
    with open(tag_file, "rb") as f:
        tag = f.read()
    with open(iv_file, "rb") as f:
        iv = f.read()
    
    # Оригинальные ассоциированные данные
    original_ad = b"Student_Group_Lab_MGM"
    
    # Расшифрование с оригинальными данными
    decrypted, auth_ok = mgm_decrypt(key, iv, ciphertext, original_ad, tag)
    print(f"С оригинальными данными: {'Аутентификация УСПЕШНА' if auth_ok else 'Аутентификация ОШИБКА'}")
    
    if auth_ok:
        decrypted_file = base_name + "_decrypted" + os.path.splitext(base_name)[1]
        with open(decrypted_file, "wb") as f:
            f.write(decrypted)
        print(f"Файл успешно расшифрован в {decrypted_file}")
    
    # Измененные ассоциированные данные
    modified_ad = b"Student_Group_Lab_MGM_MODIFIED"
    
    # Расшифрование с измененными данными
    _, auth_ok_modified = mgm_decrypt(key, iv, ciphertext, modified_ad, tag)
    print(f"С измененными данными: {'Аутентификация УСПЕШНА' if auth_ok_modified else 'Аутентификация ОШИБКА'}")
    
    if not auth_ok_modified:
        print("✓ MGM корректно обнаружил изменение ассоциированных данных!")
    print()

def main():
    """Главная функция"""
    while True:
        print("=" * 50)
        print("MGM РЕЖИМ (ГОСТ 34.13-2018)")
        print("1 - Тест из ГОСТ")
        print("2 - Зашифровать файл")
        print("3 - Проверить целостность")
        print("4 - Выход")
        
        choice = input("Выберите: ").strip()
        
        if choice == "1":
            test_mgm()
        elif choice == "2":
            file_path = input("Введите путь к файлу для шифрования: ").strip()
            encrypt_file(file_path)
        elif choice == "3":
            test_integrity()
        elif choice == "4":
            break
        else:
            print("Неверный выбор")

if __name__ == "__main__":
    main()