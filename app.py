import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from config import Config
from crypto_utils import (
    create_password_verifier,
    decrypt_value,
    derive_key,
    encrypt_value,
    generate_salt,
    InvalidToken,
    verify_password,
)
from session_store import MemorySessionInterface


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    app.session_interface = MemorySessionInterface()

    @app.teardown_appcontext
    def close_database(_error=None):
        database = g.pop("database", None)
        if database is not None:
            database.close()

    def get_database():
        if "database" not in g:
            g.database = sqlite3.connect(app.config["DATABASE"])
            g.database.row_factory = sqlite3.Row
        return g.database

    def init_database():
        database = get_database()
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_config (
                name TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        database.commit()

    def get_config_value(name):
        row = get_database().execute(
            "SELECT value FROM app_config WHERE name = ?",
            (name,),
        ).fetchone()
        return row["value"] if row else None

    def is_initialized():
        return get_config_value("password_verifier") is not None

    def current_encryption_key():
        encoded_key = session.get("encryption_key")
        return encoded_key.encode("ascii") if encoded_key else None

    def new_csrf_token():
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
        return token

    def login_required(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if current_encryption_key() is None:
                if request.path.startswith("/api/"):
                    return jsonify(error="Сессия истекла. Войдите снова."), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped_view

    @app.before_request
    def validate_csrf():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None

        supplied_token = request.headers.get("X-CSRF-Token")
        if supplied_token is None:
            supplied_token = request.form.get("csrf_token")

        expected_token = session.get("csrf_token")
        if (
            expected_token is None
            or supplied_token is None
            or not secrets.compare_digest(expected_token, supplied_token)
        ):
            if request.path.startswith("/api/"):
                return jsonify(error="Недействительный CSRF-токен."), 403
            return render_template(
                "login.html",
                error="Сессия формы истекла. Повторите попытку.",
                setup=not is_initialized(),
                csrf_token=new_csrf_token(),
            ), 403
        return None

    @app.get("/")
    def root():
        destination = "keys_page" if current_encryption_key() else "login"
        return redirect(url_for(destination))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if current_encryption_key():
                return redirect(url_for("keys_page"))
            return render_template(
                "login.html",
                setup=not is_initialized(),
                csrf_token=session.get("csrf_token") or new_csrf_token(),
            )

        password = request.form.get("password", "")
        setup = not is_initialized()
        error = None

        if len(password) < 8:
            error = "Мастер-пароль должен содержать не менее 8 символов."
        elif setup and password != request.form.get("password_confirm", ""):
            error = "Пароли не совпадают."

        if error:
            return render_template(
                "login.html",
                error=error,
                setup=setup,
                csrf_token=session["csrf_token"],
            ), 400

        database = get_database()
        salt = get_config_value("salt")
        if salt is None:
            salt = generate_salt()

        encryption_key = derive_key(password, bytes(salt))
        verifier = get_config_value("password_verifier")

        if verifier is not None and not verify_password(
            encryption_key,
            bytes(verifier).decode("ascii"),
        ):
            return render_template(
                "login.html",
                error="Неверный мастер-пароль.",
                setup=False,
                csrf_token=session["csrf_token"],
            ), 401

        if verifier is None:
            database.executemany(
                "INSERT INTO app_config (name, value) VALUES (?, ?)",
                (
                    ("salt", sqlite3.Binary(salt)),
                    (
                        "password_verifier",
                        create_password_verifier(encryption_key).encode("ascii"),
                    ),
                ),
            )
            database.commit()

        session.clear()
        session.permanent = True
        session["encryption_key"] = encryption_key.decode("ascii")
        new_csrf_token()
        return redirect(url_for("keys_page"))

    @app.get("/keys")
    @login_required
    def keys_page():
        return render_template(
            "index.html",
            csrf_token=session.get("csrf_token") or new_csrf_token(),
        )

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/api/keys")
    @login_required
    def list_keys():
        rows = get_database().execute(
            "SELECT id, name, encrypted_value, created_at "
            "FROM keys ORDER BY name COLLATE NOCASE, id"
        ).fetchall()
        key = current_encryption_key()
        result = []

        for row in rows:
            try:
                plaintext = decrypt_value(key, row["encrypted_value"])
                masked_value = mask_value(plaintext)
            except (InvalidToken, UnicodeDecodeError):
                masked_value = "Недоступно"

            result.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "masked_value": masked_value,
                    "created_at": row["created_at"],
                }
            )
        return jsonify(result)

    @app.post("/api/keys")
    @login_required
    def create_key():
        payload = request.get_json(silent=True) or {}
        name, value, error = validate_key_payload(payload, require_value=True)
        if error:
            return jsonify(error=error), 400

        cursor = get_database().execute(
            "INSERT INTO keys (name, encrypted_value) VALUES (?, ?)",
            (
                name,
                sqlite3.Binary(encrypt_value(current_encryption_key(), value)),
            ),
        )
        get_database().commit()
        return jsonify(id=cursor.lastrowid, message="Ключ добавлен."), 201

    @app.get("/api/keys/<int:key_id>/value")
    @login_required
    def get_key_value(key_id):
        row = get_database().execute(
            "SELECT encrypted_value FROM keys WHERE id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            return jsonify(error="Ключ не найден."), 404

        try:
            value = decrypt_value(
                current_encryption_key(),
                row["encrypted_value"],
            )
        except (InvalidToken, UnicodeDecodeError):
            return jsonify(error="Не удалось расшифровать ключ."), 422
        return jsonify(value=value)

    @app.put("/api/keys/<int:key_id>")
    @login_required
    def update_key(key_id):
        database = get_database()
        current = database.execute(
            "SELECT name, encrypted_value FROM keys WHERE id = ?",
            (key_id,),
        ).fetchone()
        if current is None:
            return jsonify(error="Ключ не найден."), 404

        payload = request.get_json(silent=True) or {}
        if "name" not in payload and "value" not in payload:
            return jsonify(error="Нет данных для обновления."), 400

        name = payload.get("name", current["name"])
        value = payload.get("value")
        name, value, error = validate_key_payload(
            {"name": name, "value": value},
            require_value=False,
        )
        if error:
            return jsonify(error=error), 400

        encrypted_value = current["encrypted_value"]
        if value is not None:
            encrypted_value = sqlite3.Binary(
                encrypt_value(current_encryption_key(), value)
            )

        database.execute(
            "UPDATE keys SET name = ?, encrypted_value = ? WHERE id = ?",
            (name, encrypted_value, key_id),
        )
        database.commit()
        return jsonify(message="Изменения сохранены.")

    @app.delete("/api/keys/<int:key_id>")
    @login_required
    def delete_key(key_id):
        database = get_database()
        cursor = database.execute("DELETE FROM keys WHERE id = ?", (key_id,))
        database.commit()
        if cursor.rowcount == 0:
            return jsonify(error="Ключ не найден."), 404
        return jsonify(message="Ключ удалён.")

    with app.app_context():
        init_database()

    return app


def validate_key_payload(payload, require_value):
    name = payload.get("name")
    value = payload.get("value")

    if not isinstance(name, str) or not name.strip():
        return None, None, "Укажите название сервиса."
    name = name.strip()
    if len(name) > 120:
        return None, None, "Название не должно превышать 120 символов."

    if value is not None and not isinstance(value, str):
        return None, None, "Ключ должен быть строкой."
    if require_value and not value:
        return None, None, "Укажите значение ключа."
    if value is not None and not value:
        return None, None, "Значение ключа не может быть пустым."
    if value is not None and len(value) > 10_000:
        return None, None, "Ключ слишком длинный."

    return name, value, None


def mask_value(value):
    if len(value) >= 8:
        return f"{value[:4]}****{value[-4:]}"
    return "****"


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=app.config["PORT"], debug=False)
