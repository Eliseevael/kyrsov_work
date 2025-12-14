import click

def register_cli(app):
    @app.cli.command("seed")
    def seed():
        from . import db
        from .models import User, Role

        if User.query.first():
            click.echo("Пользователи уже есть. Seed пропущен.")
            return

        users = [
            ("clerk", "clerk123", Role.CLERK),
            ("approver", "approver123", Role.APPROVER),
            ("executor", "executor123", Role.EXECUTOR),
            ("pdzk", "pdzk123", Role.PDZK),
            ("auditor", "auditor123", Role.AUDITOR),
        ]

        for username, password, role in users:
            u = User(username=username, role=role)
            u.set_password(password)
            db.session.add(u)

        db.session.commit()
        click.echo("Ок. Пользователи созданы.")
