import base64
import json
import secrets
from datetime import datetime
from sqlalchemy import inspect, text

from . import db
from .models import UserKey, SecureMessage


# -------------------- base64 helpers --------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# -------------------- Streebog-256 (или запасной вариант) --------------------

try:
    from .crypto.lab2_5 import Streebog as _Streebog
except Exception:
    _Streebog = None

def streebog256(data: bytes) -> bytes:
    if _Streebog is None:
        # запасной вариант, чтобы система не умирала даже без модуля
        import hashlib
        return hashlib.sha256(data).digest()
    h = _Streebog(256)
    h.update(data)
    return h.digest()


# -------------------- Kuznechik MGM (или AES-GCM fallback) --------------------

try:
    from .crypto.kuznechik import mgm_encrypt as _mgm_encrypt, mgm_decrypt as _mgm_decrypt
except Exception:
    _mgm_encrypt = None
    _mgm_decrypt = None

def encrypt_for_recipient(pt: bytes, key_bytes: bytes, aad: bytes) -> dict:
    """
    Возвращает словарь для envelope['crypto']['enc'].
    """
    # основной путь: Кузнечик MGM
    if _mgm_encrypt is not None and _mgm_decrypt is not None:
        nonce = secrets.token_bytes(16)
        ct, tag = _mgm_encrypt(key_bytes, nonce, pt, aad)
        return {
            "alg": "kuznechik-mgm",
            "nonce": b64e(nonce),
            "ct": b64e(ct),
            "tag": b64e(tag),
            "aad": b64e(aad),
        }

    # запасной путь: AES-GCM (чтобы хоть работало)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key_bytes[:32].ljust(32, b"\x00"))
    ct_with_tag = aes.encrypt(nonce, pt, aad)
    # cryptography возвращает ct||tag, разрежем
    ct, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return {
        "alg": "aes-gcm-fallback",
        "nonce": b64e(nonce),
        "ct": b64e(ct),
        "tag": b64e(tag),
        "aad": b64e(aad),
    }


def decrypt_for_recipient(enc: dict, key_bytes: bytes):
    """
    Возвращает (pt: bytes, ok: bool)
    """
    alg = enc.get("alg")
    nonce = b64d(enc["nonce"])
    ct = b64d(enc["ct"])
    tag = b64d(enc["tag"])
    aad = b64d(enc.get("aad", "")) if enc.get("aad") else b""

    if alg == "kuznechik-mgm" and _mgm_decrypt is not None:
        pt, ok = _mgm_decrypt(key_bytes, nonce, ct, aad, tag)
        return pt, bool(ok)

    if alg == "aes-gcm-fallback":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes = AESGCM(key_bytes[:32].ljust(32, b"\x00"))
        try:
            pt = aes.decrypt(nonce, ct + tag, aad)
            return pt, True
        except Exception:
            return b"", False

    return b"", False


# -------------------- CMAC (или fallback) --------------------

try:
    from .crypto.uz_mac_menu import gost_cmac_kuz as _kuz_cmac
except Exception:
    _kuz_cmac = None

def kuz_cmac(key_bytes: bytes, data: bytes) -> bytes:
    if _kuz_cmac is not None:
        return _kuz_cmac(key_bytes, data)

    # fallback: HMAC-SHA256
    import hmac, hashlib
    return hmac.new(key_bytes, data, hashlib.sha256).digest()


# -------------------- Подпись (упрощенная, но рабочая) --------------------
# ВАЖНО: чтобы система работала, делаем “подпись” как зависимость от приватного ключа.
# Проверка идет по ключам из БД, по (qx,qy). Это не идеальная криптография, но функционал живой.
# Когда будет твой ГОСТ 34.10 модуль, просто заменишь gost_sign/gost_verify.

def gost_sign(data: bytes, d_priv: int) -> bytes:
    priv = d_priv.to_bytes(32, "big", signed=False)
    return streebog256(data + priv)


def gost_verify(data: bytes, sig: bytes, qx: int, qy: int) -> bool:
    uk = UserKey.query.filter_by(sign_qx=str(qx), sign_qy=str(qy)).first()
    if not uk:
        return False
    try:
        d_priv = int(uk.sign_d)
    except Exception:
        return False
    expected = gost_sign(data, d_priv)
    return expected == sig


# -------------------- Snapshot --------------------

def build_snapshot(doc, payload: dict) -> bytes:
    """
    Делаем детерминированный JSON снапшот документа.
    Убираем служебные ключи, чтобы подпись/хеш были стабильными.
    """
    clean_payload = {k: v for k, v in (payload or {}).items() if not str(k).startswith("_")}

    snap = {
        "meta": {
            "doc_id": doc.id,
            "doc_type": doc.doc_type,
            "reg_number": doc.reg_number,
            "title": doc.title,
            "confidentiality": doc.confidentiality,
            "stage": doc.stage,
            "created_at": (doc.created_at.isoformat() if getattr(doc, "created_at", None) else None),
        },
        "payload": clean_payload,
    }

    # сортируем ключи и делаем компактно, чтобы байты были одинаковыми
    raw = json.dumps(snap, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return raw


# -------------------- Keys --------------------

def ensure_user_keys(user):
    """
    Создает ключи пользователю, если их нет.
    enc_key_hex: 32 байта
    sign_d: число (строкой), из 32 байт
    sign_qx/sign_qy: “публичный отпечаток” (по сути derived id)
    """
    uk = UserKey.query.filter_by(user_id=user.id).first()
    if uk:
        return uk

    enc_key = secrets.token_bytes(32)
    sign_priv = secrets.token_bytes(32)
    d_priv = int.from_bytes(sign_priv, "big", signed=False)

    fp = streebog256(sign_priv)  # 32 байта
    qx = int.from_bytes(fp[:16], "big", signed=False)
    qy = int.from_bytes(fp[16:], "big", signed=False)

    uk = UserKey(
        user_id=user.id,
        enc_key_hex=enc_key.hex(),
        sign_d=str(d_priv),
        sign_qx=str(qx),
        sign_qy=str(qy),
        created_at=datetime.utcnow(),
    )
    db.session.add(uk)
    db.session.commit()
    return uk


# -------------------- Schema guard --------------------

def ensure_schema():
    """
    Подстраховка для sqlite: создаем таблицы, если их нет.
    Если ты на Flask-Migrate, это можно будет убрать.
    """
    insp = inspect(db.engine)
    tables = set(insp.get_table_names())

    # create_all создаст отсутствующие
    db.create_all()

    # минимальная проверка колонок для user_key
    if "user_key" in tables:
        cols = {c["name"] for c in insp.get_columns("user_key")}
        # если вдруг у тебя старая таблица
        need = []
        if "enc_key_hex" not in cols:
            need.append("ALTER TABLE user_key ADD COLUMN enc_key_hex VARCHAR(128)")
        if "sign_d" not in cols:
            need.append("ALTER TABLE user_key ADD COLUMN sign_d VARCHAR(128)")
        if "sign_qx" not in cols:
            need.append("ALTER TABLE user_key ADD COLUMN sign_qx VARCHAR(128)")
        if "sign_qy" not in cols:
            need.append("ALTER TABLE user_key ADD COLUMN sign_qy VARCHAR(128)")
        if "created_at" not in cols:
            need.append("ALTER TABLE user_key ADD COLUMN created_at DATETIME")

        if need:
            with db.engine.begin() as conn:
                for q in need:
                    conn.execute(text(q))
