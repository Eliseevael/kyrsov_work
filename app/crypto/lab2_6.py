import secrets
import os
from typing import Tuple, Optional


class Stribog:
    def __init__(self, hash_size: int = 512):
        if hash_size not in (256, 512):
            raise ValueError("hash_size должен быть 256 или 512")
        self.hash_size = hash_size
        self.buffer = bytearray()
        self.h = bytearray(64)
        self.N = bytearray(64)
        self.Sigma = bytearray(64)

        # Инициализационный вектор (как в ГОСТ: для 256 бит начинается с 0x01)
        if hash_size == 256:
            self.h = bytearray([1] + [0] * 63)

        
        self.S_box = list(range(256))
        self.tau = list(range(64))

        # 12 псевдо-констант по 512 бит каждая
        self.C = [bytes([i + 1]) * 64 for i in range(12)]

    

    def _add_modulo_2_512(self, a: bytearray, b: bytearray) -> bytearray:
        res = bytearray(64)
        carry = 0
        for i in range(63, -1, -1):
            s = a[i] + b[i] + carry
            res[i] = s & 0xFF
            carry = s >> 8
        return res

    def _S(self, data: bytearray) -> bytearray:
        return bytearray(self.S_box[b] for b in data)

    def _P(self, data: bytearray) -> bytearray:
        res = bytearray(64)
        for i, t in enumerate(self.tau):
            res[t] = data[i]
        return res

    def _L(self, data: bytearray) -> bytearray:
        res = bytearray(64)
        for i in range(64):
            v = data[i]
            res[i] = ((v << 1) ^ (v >> 1)) & 0xFF
        return res

    def _LPS(self, data: bytearray) -> bytearray:
        return self._L(self._P(self._S(data)))

    def _E(self, K: bytearray, m: bytearray) -> bytearray:
        state = bytearray(m)
        for i in range(12):
            # XOR с ключом
            for j in range(64):
                state[j] ^= K[j]
            # LPS
            state = self._LPS(state)
            # следующий ключ
            if i < 11:
                K = self._LPS(self._add_modulo_2_512(K, bytearray(self.C[i])))
        return state

    def _g(self, N: bytearray, h: bytearray, m: bytearray) -> bytearray:
        K = self._LPS(self._add_modulo_2_512(h, N))
        Ekm = self._E(K, m)
        out = bytearray(64)
        for i in range(64):
            out[i] = h[i] ^ Ekm[i] ^ m[i]
        return out

    

    def update(self, data: bytes) -> None:
        self.buffer.extend(data)
        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self.buffer = self.buffer[64:]
            self.h = self._g(self.N, self.h, bytearray(block))
            # увеличиваем счётчик N (условно +512 бит)
            self.N = self._add_modulo_2_512(self.N, bytearray([0] * 63 + [0x01]))
            # суммируем сообщение
            self.Sigma = self._add_modulo_2_512(self.Sigma, bytearray(block))

    def finalize(self) -> bytes:
        # Дополняем последний блок: данные, затем 0x01 и нули до 64 байт
        if len(self.buffer) < 64:
            pad = bytearray(self.buffer)
            pad.append(0x01)
            pad.extend(b"\x00" * (64 - len(pad)))
            block = pad
        else:
            block = bytearray(self.buffer[:64])

        self.h = self._g(self.N, self.h, block)

        # Для 256-битного варианта берём правые 256 бит
        if self.hash_size == 256:
            return bytes(self.h[32:])
        return bytes(self.h)

    def hash(self, data: bytes) -> bytes:
        # Сброс состояния и хэш целиком
        self.__init__(self.hash_size)
        self.update(data)
        return self.finalize()



class GOST3410_2018:
    def __init__(self):
        # Параметры кривой (пример с p, a, b, q и базовой точкой P)
        self.p = 0x8000000000000000000000000000000000000000000000000000000000000431
        self.a = 7
        self.b = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
        self.q = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3

        # Базовая точка
        self.P = (
            0x2,
            0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
        )

        
        self.d = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28

        # Хэш-функция (256 бит)
        self.hasher = Stribog(256)

        # Публичный ключ: Q = d * P (чисто по определению, без ошибок из PDF)
        self.Q = self.point_mult(self.d, self.P)

    

    def mod_inverse(self, a: int, m: int) -> int:
        return pow(a, -1, m)

    def point_add(
        self, P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]
    ) -> Optional[Tuple[int, int]]:
        if P1 is None:
            return P2
        if P2 is None:
            return P1

        x1, y1 = P1
        x2, y2 = P2

        if x1 == x2:
            # P1 == ±P2
            if (y1 + y2) % self.p == 0:
                return None  # бесконечно удалённая точка
            # удвоение
            lam = (3 * x1 * x1 + self.a) * self.mod_inverse(2 * y1 % self.p, self.p) % self.p
        else:
            # сложение разных точек
            lam = (y2 - y1) * self.mod_inverse((x2 - x1) % self.p, self.p) % self.p

        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_mult(self, k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        R = None
        add = P
        while k > 0:
            if k & 1:
                R = self.point_add(R, add)
            add = self.point_add(add, add)
            k >>= 1
        return R

   

    def sign_message(self, message: bytes, private_key: int) -> Tuple[int, int]:
        # 1. Хэш сообщения
        h_bytes = self.hasher.hash(message)
        h = int.from_bytes(h_bytes, "little") % self.q
        if h == 0:
            h = 1

        # 2. Генерация случайного k и расчёт подписи (r, s)
        while True:
            k = secrets.randbelow(self.q - 1) + 1  # 1 <= k <= q-1
            C = self.point_mult(k, self.P)
            if C is None:
                continue

            r = C[0] % self.q
            if r == 0:
                continue

            s = (r * private_key + k * h) % self.q
            if s != 0:
                return (r, s)

    def verify_signature(
        self, message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int]
    ) -> bool:
        r, s = signature

        # 1. Проверка диапазонов
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        # 2. Хэш сообщения
        h_bytes = self.hasher.hash(message)
        h = int.from_bytes(h_bytes, "little") % self.q
        if h == 0:
            h = 1

        # 3. Вычисление вспомогательных величин
        v = self.mod_inverse(h, self.q)
        z1 = (s * v) % self.q
        z2 = (-r * v) % self.q

        # 4. Точка C = z1 * P + z2 * Q
        C1 = self.point_mult(z1, self.P)
        C2 = self.point_mult(z2, public_key)
        C = self.point_add(C1, C2)
        if C is None:
            return False

        R = C[0] % self.q
        return R == r




def read_file_bytes(file_path: str) -> Optional[bytes]:
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
        return None


def save_signature(signature: Tuple[int, int], file_path: str) -> None:
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"r: {hex(signature[0])}\n")
            f.write(f"s: {hex(signature[1])}\n")
        print(f"Подпись сохранена в файл: {file_path}")
    except Exception as e:
        print(f"Ошибка сохранения подписи: {e}")


def load_signature(file_path: str) -> Optional[Tuple[int, int]]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        r = int(lines[0].split(":")[1].strip(), 16)
        s = int(lines[1].split(":")[1].strip(), 16)
        return (r, s)
    except Exception as e:
        print(f"Ошибка загрузки подписи: {e}")
        return None



def test_stribog() -> None:
    print("=== ТЕСТ ХЭШ-ФУНКЦИИ (УПРОЩЁННЫЙ СТРИБОГ) ===")
    msg = b"0123456789"
    h256 = Stribog(256).hash(msg)
    h512 = Stribog(512).hash(msg)
    print("Сообщение:", msg)
    print("Хэш 256 бит:", h256.hex())
    print("Хэш 512 бит:", h512.hex())
    print("=" * 60)


def test_gost_example() -> None:
    print("=== ТЕСТ ЭЦП: ФОРМИРОВАНИЕ И ПРОВЕРКА ===")
    gost = GOST3410_2018()
    message = b"Test message for GOST 34.10-2018"
    print("Сообщение:", message)

    signature = gost.sign_message(message, gost.d)
    r, s = signature
    print("Подпись сформирована:")
    print("r =", hex(r))
    print("s =", hex(s))

    ok = gost.verify_signature(message, signature, gost.Q)
    print("Проверка подписи:", "ПОДПИСЬ ВЕРНА" if ok else "ПОДПИСЬ НЕВЕРНА")
    print("=" * 60)




def main() -> None:
    gost = GOST3410_2018()

    while True:
        print("\n=== ПРОГРАММА ЭЦП ПО ГОСТ 34.10-2018 ===")
        print("1. Проверка по госту")
        print("2. Сформировать электронную подпись файла")
        print("3. Проверить электронную подпись файла")
        print("5. Выход")

        choice = input("Выберите режим работы (1–5): ").strip()

        if choice == "1":
            test_gost_example()

        elif choice == "2":
            file_path = input("Введите путь к файлу для подписания: ").strip()
            if not os.path.exists(file_path):
                print("Файл не существует.")
                continue

            data = read_file_bytes(file_path)
            if data is None:
                continue

            print("Формирование подписи...")
            signature = gost.sign_message(data, gost.d)
            r, s = signature
            print("Подпись сформирована:")
            print("r:", hex(r))
            print("s:", hex(s))

            save_choice = input("Сохранить подпись в файл? (y/n): ").strip().lower()
            if save_choice == "y":
                sig_path = input("Введите путь для сохранения подписи: ").strip()
                save_signature(signature, sig_path)

        elif choice == "3":
            file_path = input("Введите путь к файлу для проверки: ").strip()
            sig_path = input("Введите путь к файлу с подписью: ").strip()

            if not os.path.exists(file_path):
                print("Файл для проверки не существует.")
                continue
            if not os.path.exists(sig_path):
                print("Файл с подписью не существует.")
                continue

            data = read_file_bytes(file_path)
            signature = load_signature(sig_path)

            if data is None or signature is None:
                continue

            print("Проверка подписи...")
            ok = gost.verify_signature(data, signature, gost.Q)
            if ok:
                print("ЭЛЕКТРОННАЯ ПОДПИСЬ ВЕРНА")
                print("Документ не был изменён после подписания.")
            else:
                print(" ЭЛЕКТРОННАЯ ПОДПИСЬ НЕВЕРНА")
                print("Документ изменён или подпись некорректна.")

        elif choice == "4":
            test_stribog()

        elif choice == "5":
            print("Выход из программы.")
            break

        else:
            print("Неверный выбор. Повторите.")


if __name__ == "__main__":
    
    g = GOST3410_2018()
    msg = b"self test message"
    sig = g.sign_message(msg, g.d)
    print("Самотест. Подпись проходит проверку:", g.verify_signature(msg, sig, g.Q))
    
    main()
