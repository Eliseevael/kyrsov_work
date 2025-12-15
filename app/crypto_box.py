# app/crypto_box.py
import base64
import json
import os
import secrets
from pathlib import Path
from datetime import datetime

from flask import current_app

from .crypto_src.kuznechik import mgm_encrypt, mgm_decrypt
from .crypto_src.lab2_6 import Stribog, GOST3410_2018


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def _keys_path() -> Path:
    return Path(current_app.instance_path) / "crypto_keys.json"


def _load_keys() -> dict:
    p = _keys_path()
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8") or "{}")


def _save_keys(data: dict) -> None:
    p = _keys_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _ensure_user_keys(user_id: int) -> dict:
    """
    Для прототипа храним:
    - ЭЦП ключи ГОСТ 34.10-2018: d (закрытый), Q (открытый)
    """
    store = _load_keys()
    k = str(user_id)

    if k in store:
        return store[k]

    gost = GOST3410_2018()  # используем твои параметры кривой
    d = secrets.randbelow(gost.q - 1) + 1
    Q = gost.point_mult(d, gost.G)

    store[k] = {
        "sign": {
            "d_hex": hex(d),
            "Q": [hex(Q[0]), hex(Q[1])],
        }
    }
    _save_keys(store)
    return store[k]


def get_sign_private(user_id: int) -> int:
    data = _ensure_user_keys(user_id)
    return int(data["sign"]["d_hex"], 16)


def get_sign_public(user_id: int) -> tuple[int, int]:
    data = _ensure_user_keys(user_id)
    x = int(data["sign"]["Q"][0], 16)
    y = int(data["sign"]["Q"][1], 16)
    return (x, y)


def stribog256(data: bytes) -> bytes:
    h = Stribog(256)
    return h.hash(data)


def sign_bytes(user_id: int, data: bytes) -> dict:
    """
    Подпись делаем по хешу (Стрибог-256).
    Возвращаем r,s как hex строки.
    """
    gost = GOST3410_2018()
    d = get_sign_private(user_id)
    Q = get_sign_public(user_id)

    gost.d = d
    gost.Q = Q

    digest = stribog256(data)
    r, s = gost.sign_message(digest.decode("latin1", errors="ignore"))
    # ВНИМАНИЕ: твой sign_message сейчас ждёт строку.
    # Чтобы было строго по байтам, лучше ниже заменить sign_message на sign_hash_int,
    # но для прототипа оставим так, чтобы не ломать твой код.

    return {"r": hex(r), "s": hex(s), "alg": "ГОСТ 34.10-2018", "at": datetime.utcnow().isoformat()}


def verify_bytes(signer_user_id: int, data: bytes, sig: dict) -> bool:
    gost = GOST3410_2018()
    gost.Q = get_sign_public(signer_user_id)

    digest = stribog256(data)
    r = int(sig["r"], 16)
    s = int(sig["s"], 16)
    return gost.verify_signature(digest.decode("latin1", errors="ignore"), (r, s))


def derive_kuz_key(sender_id: int, recipient_id: int, doc_id: int) -> bytes:
    """
    Для прототипа делаем ключ из Стрибога по “контексту”.
    Это не ECDH. Но:
    - работает,
    - показывает механику,
    - и ты позже спокойно заменишь на нормальный обмен (у тебя он тоже есть в работах).
    """
    seed = f"zedkd|doc:{doc_id}|from:{sender_id}|to:{recipient_id}".encode("utf-8")
    return stribog256(seed)  # 32 байта


def encrypt_payload(doc_id: int, sender_id: int, recipient_id: int, plaintext: bytes) -> dict:
    key = derive_kuz_key(sender_id, recipient_id, doc_id)
    iv = os.urandom(12)
    ad = f"doc:{doc_id}|from:{sender_id}|to:{recipient_id}".encode("utf-8")

    ct, tag = mgm_encrypt(key, iv, ad, plaintext)

    signed_blob = iv + tag + ct
    sig = sign_bytes(sender_id, signed_blob)

    return {
        "on": True,
        "alg": "Кузнечик-МГМ",
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "iv_b64": b64e(iv),
        "ad_b64": b64e(ad),
        "ct_b64": b64e(ct),
        "tag_b64": b64e(tag),
        "hash_alg": "Стрибог-256",
        "hash_plain_b64": b64e(stribog256(plaintext)),
        "sig": sig,
    }


def decrypt_payload(doc_id: int, me_id: int, secure: dict) -> tuple[bytes, dict]:
    sender_id = int(secure["sender_id"])
    recipient_id = int(secure["recipient_id"])

    if me_id not in (sender_id, recipient_id):
        raise PermissionError("Нет прав на расшифровку")

    key = derive_kuz_key(sender_id, recipient_id, doc_id)
    iv = b64d(secure["iv_b64"])
    ad = b64d(secure["ad_b64"])
    ct = b64d(secure["ct_b64"])
    tag = b64d(secure["tag_b64"])

    # имитовставка проверяется внутри mgm_decrypt (если тег не совпал, будет исключение)
    pt = mgm_decrypt(key, iv, ad, ct, tag)

    signed_blob = iv + tag + ct
    sig_ok = verify_bytes(sender_id, signed_blob, secure["sig"])

    meta = {
        "sig_ok": bool(sig_ok),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
    }
    return pt, meta
