from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager


class Role:
    CLERK = "clerk"          # делопроизводитель
    APPROVER = "approver"    # генеральный директор
    EXECUTOR = "executor"    # исполнитель
    PDZK = "pdzk"            # комиссия
    AUDITOR = "auditor"      # наблюдатель


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False, default=Role.CLERK)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class DocumentType:
    LETTER = "letter"
    INSTRUCTION = "instruction"
    PACKET = "packet"


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doc_type = db.Column(db.String(30), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    reg_number = db.Column(db.String(50), nullable=True)

    stage = db.Column(db.String(50), nullable=False, default="created")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by = db.relationship("User", backref="created_documents")

    content_json = db.Column(db.Text, nullable=False, server_default="{}")
    confidentiality = db.Column(db.String(50), nullable=True)

    # важно: у тебя main.py это использует
    assigned_to_role = db.Column(db.String(30), nullable=True)

    # новое: защищенный контейнер
    security_json = db.Column(db.Text, nullable=True)



class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    action = db.Column(db.String(80), nullable=False)
    from_stage = db.Column(db.String(50), nullable=True)
    to_stage = db.Column(db.String(50), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comment = db.Column(db.String(500), nullable=True)

    document = db.relationship("Document", backref="events")
    actor = db.relationship("User", backref="events")


# --------- ключи пользователя (чтобы не ломать таблицу user) ---------
class UserKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    user = db.relationship("User", backref=db.backref("keys", uselist=False))

    # симметричный ключ (Кузнечик) 32 байта в hex
    enc_key_hex = db.Column(db.String(64), nullable=False)

    # ЭЦП (ГОСТ 34.10-2018): приватный ключ d и публичный Q=(x,y) как строки чисел
    sign_d = db.Column(db.Text, nullable=False)
    sign_qx = db.Column(db.Text, nullable=False)
    sign_qy = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --------- защищенная “пересылка” документа между пользователями ---------
class SecureMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=True)

    envelope_json = db.Column(db.Text, nullable=False)  # конверт: шифртекст/iv/tag/хеш/имито/подпись
    status = db.Column(db.String(20), nullable=False, default="new")  # new/opened/accepted

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    opened_at = db.Column(db.DateTime, nullable=True)

    from_user = db.relationship("User", foreign_keys=[from_user_id], backref="out_secure")
    to_user = db.relationship("User", foreign_keys=[to_user_id], backref="in_secure")
    document = db.relationship("Document", backref="secure_messages")
