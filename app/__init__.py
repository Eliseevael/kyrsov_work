from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from sqlalchemy import inspect, text

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def ensure_user_columns():
    from .models import User
    table = getattr(User, "__tablename__", "user")
    insp = inspect(db.engine)

    if table not in insp.get_table_names():
        return

    cols = {c["name"] for c in insp.get_columns(table)}
    to_add = []

    if "full_name" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN full_name VARCHAR(120)")
    if "position" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN position VARCHAR(120)")
    if "email" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN email VARCHAR(120)")
    if "phone" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN phone VARCHAR(40)")
    if "is_active" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN is_active BOOLEAN DEFAULT 1")
    if "created_at" not in cols:
        to_add.append(f"ALTER TABLE {table} ADD COLUMN created_at DATETIME")

    if not to_add:
        return

    with db.engine.begin() as conn:
        for sql in to_add:
            conn.execute(text(sql))

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret-key-change-me"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///zedkd.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    migrate.init_app(app, db)

    from .auth import auth_bp
    from .main import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # ВАЖНО: импорт CLI только здесь, когда db уже создан
    from .cli import register_cli
    register_cli(app)

    return app
