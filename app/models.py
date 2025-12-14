from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, login_manager


class Role:
    CLERK = "clerk"          # делопроизводитель
    APPROVER = "approver"    # согласование/утверждение
    EXECUTOR = "executor"    # исполнитель
    PDZK = "pdzk"            # комиссия
    AUDITOR = "auditor"      # наблюдатель


class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False, default=Role.CLERK)

    def set_password(self, password: str) -> None:
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
    __tablename__ = "document"

    id = db.Column(db.Integer, primary_key=True)
    doc_type = db.Column(db.String(30), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    reg_number = db.Column(db.String(50), nullable=True)

    stage = db.Column(db.String(50), nullable=False, default="created")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by = db.relationship("User", backref="created_documents")

    # кто должен обработать документ дальше (для "Входящих")
    assigned_to_role = db.Column(db.String(30), nullable=True, index=True)

    # содержимое
    content_json = db.Column(db.Text, nullable=False, server_default="{}")

    # гриф/конфиденциальность
    confidentiality = db.Column(db.String(50), nullable=True)


class AuditEvent(db.Model):
    __tablename__ = "audit_event"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    action = db.Column(db.String(120), nullable=False)
    from_stage = db.Column(db.String(50), nullable=True)
    to_stage = db.Column(db.String(50), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comment = db.Column(db.String(500), nullable=True)

    document = db.relationship("Document", backref="events")
    actor = db.relationship("User", backref="events")
