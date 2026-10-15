from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


HOST = "127.0.0.1"
PORT = 8000
PROJECT_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = PROJECT_DIR / "uploads"
DATABASE_PATH = PROJECT_DIR / "flash-bang.db"
ADMIN_CONFIG_PATH = PROJECT_DIR / ".flash-bang-admin.json"
SESSION_COOKIE = "flash_bang_session"
SESSION_LIFETIME = 365 * 24 * 60 * 60
MAX_UPLOAD_SIZE = 100 * 1024 * 1024
MAX_REQUEST_SIZE = MAX_UPLOAD_SIZE + 1024 * 1024
PASSWORD_ITERATIONS = 600_000

ALLOWED_EXTENSIONS = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
}


class APIError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, address: tuple[str, int], password_salt: bytes, password_hash: bytes
    ) -> None:
        super().__init__(address, AdminHandler)
        self.password_salt = password_salt
        self.password_hash = password_hash


def connect_database() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)
    with connect_database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS media (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                extension TEXT NOT NULL,
                category_id INTEGER NOT NULL REFERENCES categories(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS site_settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO site_settings (name, value)
            VALUES (
                'privacy_policy',
                'Политика конфиденциальности\n\nСайт не использует аналитику и не собирает персональные данные посетителей. В админ-панели используется техническая cookie для сохранения входа администратора. Загруженные фото, видео и названия категорий хранятся на компьютере, где запущен сервер.'
            );
            """
        )


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


def _save_password(password: str) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    password_hash = _hash_password(password, salt)
    config = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(password_hash).decode("ascii"),
    }
    ADMIN_CONFIG_PATH.write_text(json.dumps(config), encoding="utf-8")
    return salt, password_hash


def load_or_create_password() -> tuple[bytes, bytes]:
    if ADMIN_CONFIG_PATH.exists():
        try:
            config = json.loads(ADMIN_CONFIG_PATH.read_text(encoding="utf-8"))
            salt = base64.b64decode(config["salt"], validate=True)
            password_hash = base64.b64decode(
                config["password_hash"], validate=True
            )
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Не удалось прочитать настройки пароля {ADMIN_CONFIG_PATH}: {error}"
            ) from error
        if len(salt) != 16 or len(password_hash) != hashlib.sha256().digest_size:
            raise RuntimeError(f"Некорректные настройки пароля: {ADMIN_CONFIG_PATH}")
        return salt, password_hash

    password = os.environ.get("FLASH_BANG_ADMIN_PASSWORD")
    if password is None:
        print("Первый запуск: придумай пароль администратора.", flush=True)
        password = getpass.getpass("Пароль (минимум 12 символов): ")
        confirmation = getpass.getpass("Повтори пароль: ")
        if not hmac.compare_digest(password, confirmation):
            raise RuntimeError("Пароли не совпали. Запусти сервер ещё раз.")
    if len(password) < 12:
        raise RuntimeError("Пароль администратора должен быть не короче 12 символов.")

    salt, password_hash = _save_password(password)
    print(f"Пароль сохранён в виде хеша: {ADMIN_CONFIG_PATH.name}", flush=True)
    return salt, password_hash


class AdminHandler(BaseHTTPRequestHandler):
    server: AdminServer

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self'; media-src 'self'; "
            "style-src 'self'; script-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, format_string: str, *args: object) -> None:
        sys.stderr.write(
            f"{self.address_string()} - {format_string % args}\n"
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        content: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def _send_json(
        self,
        status: HTTPStatus,
        data: dict[str, object],
        headers: dict[str, str] | None = None,
    ) -> None:
        content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, content, "application/json; charset=utf-8", headers)

    def _read_body(self, maximum: int = MAX_REQUEST_SIZE) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise APIError(
                HTTPStatus.LENGTH_REQUIRED, "Не указан размер запроса."
            ) from error
        if length < 0:
            raise APIError(HTTPStatus.BAD_REQUEST, "Некорректный размер запроса.")
        if length > maximum:
            raise APIError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Файл слишком большой.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise APIError(HTTPStatus.BAD_REQUEST, "Запрос передан не полностью.")
        return body

    def _session_token(self) -> str | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None:
            return None
        return morsel.value

    def _is_authenticated(self) -> bool:
        token = self._session_token()
        if token is None or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return False
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        with connect_database() as connection:
            session = connection.execute(
                "SELECT expires_at FROM admin_sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if session is None:
                return False
            if session["expires_at"] <= now:
                connection.execute(
                    "DELETE FROM admin_sessions WHERE token_hash = ?", (token_hash,)
                )
                return False
            return True

    def _require_authentication(self) -> bool:
        if self._is_authenticated():
            return True
        self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Войди в админ-панель."})
        return False

    def _check_same_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://{self.headers.get('Host', '')}":
            raise APIError(HTTPStatus.FORBIDDEN, "Запрос с другого сайта запрещён.")

    def _serve_file(self, file_path: Path, content_type: str) -> None:
        try:
            content = file_path.read_bytes()
        except OSError as error:
            self.log_error("Не удалось прочитать файл %s: %s", file_path, error)
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Файл не найден."})
            return
        self._send_bytes(HTTPStatus.OK, content, content_type)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._serve_file(PROJECT_DIR / "index.html", "text/html; charset=utf-8")
            return
        if path == "/admin":
            self._serve_file(PROJECT_DIR / "admin.html", "text/html; charset=utf-8")
            return
        if path == "/privacy":
            self._serve_file(PROJECT_DIR / "privacy.html", "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self._serve_file(PROJECT_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if path == "/public.js":
            self._serve_file(
                PROJECT_DIR / "public.js",
                "text/javascript; charset=utf-8",
            )
            return
        if path == "/privacy.js":
            self._serve_file(
                PROJECT_DIR / "privacy.js",
                "text/javascript; charset=utf-8",
            )
            return
        if path == "/admin.js":
            self._serve_file(
                PROJECT_DIR / "admin.js",
                "text/javascript; charset=utf-8",
            )
            return
        if path == "/api/session":
            self._send_json(HTTPStatus.OK, {"authenticated": self._is_authenticated()})
            return
        if path == "/api/public/media":
            with connect_database() as connection:
                rows = connection.execute(
                    """
                    SELECT media.id, media.original_name, media.extension,
                           media.created_at, categories.name AS category_name
                    FROM media
                    JOIN categories ON categories.id = media.category_id
                    ORDER BY media.created_at DESC, media.rowid DESC
                    """
                ).fetchall()
            self._send_json(HTTPStatus.OK, {"media": [dict(row) for row in rows]})
            return
        if path == "/api/privacy":
            with connect_database() as connection:
                setting = connection.execute(
                    "SELECT value FROM site_settings WHERE name = 'privacy_policy'"
                ).fetchone()
            if setting is None:
                raise RuntimeError("Не найдена настройка политики конфиденциальности.")
            self._send_json(HTTPStatus.OK, {"text": setting["value"]})
            return
        if path == "/api/categories":
            if self._require_authentication():
                with connect_database() as connection:
                    categories = connection.execute(
                        """
                        SELECT categories.id, categories.name, COUNT(media.id) AS media_count
                        FROM categories
                        LEFT JOIN media ON media.category_id = categories.id
                        GROUP BY categories.id
                        ORDER BY categories.name COLLATE NOCASE
                        """
                    ).fetchall()
                self._send_json(
                    HTTPStatus.OK,
                    {"categories": [dict(category) for category in categories]},
                )
            return
        if path == "/api/media":
            if self._require_authentication():
                with connect_database() as connection:
                    rows = connection.execute(
                        """
                        SELECT media.id, media.original_name, media.extension,
                               media.created_at, categories.id AS category_id,
                               categories.name AS category_name
                        FROM media
                        JOIN categories ON categories.id = media.category_id
                        ORDER BY media.created_at DESC, media.rowid DESC
                        """
                    ).fetchall()
                self._send_json(
                    HTTPStatus.OK,
                    {"media": [dict(row) for row in rows]},
                )
            return
        if path.startswith("/uploads/"):
            media_id = path.removeprefix("/uploads/")
            if not re.fullmatch(r"[a-f0-9]{32}", media_id):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Файл не найден."})
                return
            with connect_database() as connection:
                row = connection.execute(
                    "SELECT extension FROM media WHERE id = ?", (media_id,)
                ).fetchone()
            if row is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Файл не найден."})
                return
            content_type = ALLOWED_EXTENSIONS[row["extension"]]
            self._serve_file(UPLOAD_DIR / f"{media_id}{row['extension']}", content_type)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Страница не найдена."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            self._check_same_origin()
            if path == "/api/login":
                self._login()
                return
            if path == "/api/logout":
                if self._require_authentication():
                    self._logout()
                return
            if path == "/api/privacy":
                if self._require_authentication():
                    self._save_privacy_policy()
                return
            if not self._require_authentication():
                return
            if path == "/api/categories":
                self._create_category()
            elif path == "/api/categories/delete":
                self._delete_category()
            elif path == "/api/upload":
                self._upload_media()
            elif path == "/api/media/delete":
                self._delete_media()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Страница не найдена."})
        except APIError as error:
            self._send_json(error.status, {"error": str(error)})
        except sqlite3.Error:
            self.log_error("Ошибка базы данных при обработке %s", path)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Ошибка базы данных. Подробности есть в окне сервера."},
            )

    def _login(self) -> None:
        body = self._read_body(8192)
        fields = parse_qs(body.decode("utf-8"), strict_parsing=False)
        supplied = fields.get("password", [""])[0]
        candidate = _hash_password(supplied, self.server.password_salt)
        if not hmac.compare_digest(candidate, self.server.password_hash):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Неверный пароль."})
            return

        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + SESSION_LIFETIME
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with connect_database() as connection:
            connection.execute(
                "INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)",
                (token_hash, expires_at),
            )
        cookie = (
            f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; "
            f"Path=/; Max-Age={SESSION_LIFETIME}"
        )
        self._send_json(
            HTTPStatus.OK,
            {"authenticated": True},
            {"Set-Cookie": cookie},
        )

    def _logout(self) -> None:
        token = self._session_token()
        if token is not None and re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            with connect_database() as connection:
                connection.execute(
                    "DELETE FROM admin_sessions WHERE token_hash = ?", (token_hash,)
                )
        self._send_json(
            HTTPStatus.OK,
            {"authenticated": False},
            {"Set-Cookie": f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
        )

    def _read_form(self) -> dict[str, str]:
        body = self._read_body(16_384)
        fields = parse_qs(body.decode("utf-8"), strict_parsing=False)
        return {name: values[0] for name, values in fields.items() if values}

    def _save_privacy_policy(self) -> None:
        if not self.headers.get("Content-Type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            raise APIError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Ожидалась форма.")
        fields = self._read_form()
        text = fields.get("text", "").strip()
        if not text or len(text) > 20_000:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "Политика должна содержать от 1 до 20 000 символов.",
            )
        with connect_database() as connection:
            connection.execute(
                """
                INSERT INTO site_settings (name, value)
                VALUES ('privacy_policy', ?)
                ON CONFLICT(name) DO UPDATE SET value = excluded.value
                """,
                (text,),
            )
        self._send_json(HTTPStatus.OK, {"saved": True})

    def _create_category(self) -> None:
        if not self.headers.get("Content-Type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            raise APIError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Ожидалась форма.")
        fields = self._read_form()
        name = fields.get("name", "").strip()
        if not name or len(name) > 40 or not name.isprintable():
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "Название категории должно содержать от 1 до 40 печатных символов.",
            )
        try:
            with connect_database() as connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
                category_id = cursor.lastrowid
        except sqlite3.IntegrityError as error:
            raise APIError(
                HTTPStatus.CONFLICT, "Категория с таким названием уже существует."
            ) from error
        self._send_json(
            HTTPStatus.CREATED,
            {"id": category_id, "name": name},
        )

    def _delete_category(self) -> None:
        if not self.headers.get("Content-Type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            raise APIError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Ожидалась форма.")
        fields = self._read_form()
        try:
            category_id = int(fields.get("id", ""))
        except ValueError as error:
            raise APIError(HTTPStatus.BAD_REQUEST, "Некорректная категория.") from error
        with connect_database() as connection:
            category = connection.execute(
                "SELECT id FROM categories WHERE id = ?", (category_id,)
            ).fetchone()
            if category is None:
                raise APIError(HTTPStatus.NOT_FOUND, "Категория не найдена.")
            media_count = connection.execute(
                "SELECT COUNT(*) FROM media WHERE category_id = ?", (category_id,)
            ).fetchone()[0]
            if media_count:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "Сначала удали файлы из этой категории.",
                )
            connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        self._send_json(HTTPStatus.OK, {"deleted": True})

    def _upload_media(self) -> None:
        fields: dict[str, str] = {}
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            raise APIError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Ожидалась форма загрузки.")
        body = self._read_body()
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
            + body
        )
        if not message.is_multipart():
            raise APIError(HTTPStatus.BAD_REQUEST, "Не удалось прочитать форму.")
        upload_parts: list[tuple[str, str, bytes]] = []
        for part in message.iter_parts():
            filename = part.get_filename()
            if filename is None:
                key = part.get_param("name", header="content-disposition")
                if key:
                    value = part.get_payload(decode=True)
                    if isinstance(value, bytes):
                        fields[key] = value.decode("utf-8")
                continue
            filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
            if not filename or len(filename) > 255:
                raise APIError(HTTPStatus.BAD_REQUEST, "Некорректное имя файла.")
            extension = Path(filename).suffix.lower()
            if extension not in ALLOWED_EXTENSIONS:
                raise APIError(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Разрешены JPG, PNG, GIF, WEBP, MP4, MOV и WEBM.",
                )
            content = part.get_payload(decode=True)
            if not isinstance(content, bytes) or not content:
                raise APIError(HTTPStatus.BAD_REQUEST, "Файл пустой.")
            if len(content) > MAX_UPLOAD_SIZE:
                raise APIError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "Максимальный размер одного файла — 100 МБ.",
                )
            if not _matches_file_type(extension, content):
                raise APIError(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Содержимое файла не соответствует его расширению.",
                )
            upload_parts.append((filename, extension, content))

        if len(upload_parts) != 1:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "За одну загрузку выбери ровно один файл.",
            )
        try:
            category_id = int(fields.get("category_id", ""))
        except ValueError as error:
            raise APIError(HTTPStatus.BAD_REQUEST, "Выбери категорию.") from error

        filename, extension, content = upload_parts[0]
        media_id = uuid.uuid4().hex
        destination = UPLOAD_DIR / f"{media_id}{extension}"
        with connect_database() as connection:
            exists = connection.execute(
                "SELECT 1 FROM categories WHERE id = ?", (category_id,)
            ).fetchone()
            if exists is None:
                raise APIError(HTTPStatus.BAD_REQUEST, "Выбранная категория не найдена.")
            try:
                destination.write_bytes(content)
                connection.execute(
                    """
                    INSERT INTO media (id, original_name, extension, category_id)
                    VALUES (?, ?, ?, ?)
                    """,
                    (media_id, filename, extension, category_id),
                )
            except OSError as error:
                destination.unlink(missing_ok=True)
                raise APIError(
                    HTTPStatus.INSUFFICIENT_STORAGE, "Не удалось сохранить файл."
                ) from error
            except sqlite3.Error:
                destination.unlink(missing_ok=True)
                raise
        self._send_json(
            HTTPStatus.CREATED,
            {
                "id": media_id,
                "original_name": filename,
                "extension": extension,
                "category_id": category_id,
            },
        )

    def _delete_media(self) -> None:
        if not self.headers.get("Content-Type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            raise APIError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Ожидалась форма.")
        fields = self._read_form()
        media_id = fields.get("id", "")
        if not re.fullmatch(r"[a-f0-9]{32}", media_id):
            raise APIError(HTTPStatus.BAD_REQUEST, "Некорректный файл.")
        with connect_database() as connection:
            row = connection.execute(
                "SELECT extension FROM media WHERE id = ?", (media_id,)
            ).fetchone()
            if row is None:
                raise APIError(HTTPStatus.NOT_FOUND, "Файл не найден.")
            file_path = UPLOAD_DIR / f"{media_id}{row['extension']}"
            try:
                file_path.unlink(missing_ok=True)
            except OSError as error:
                raise APIError(
                    HTTPStatus.INSUFFICIENT_STORAGE, "Не удалось удалить файл."
                ) from error
            connection.execute("DELETE FROM media WHERE id = ?", (media_id,))
        self._send_json(HTTPStatus.OK, {"deleted": True})


def _matches_file_type(extension: str, content: bytes) -> bool:
    if extension in {".jpg", ".jpeg"}:
        return content.startswith(b"\xff\xd8\xff")
    if extension == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if extension == ".gif":
        return content.startswith((b"GIF87a", b"GIF89a"))
    if extension == ".webp":
        return len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP"
    if extension in {".mp4", ".mov"}:
        return len(content) >= 12 and content[4:8] == b"ftyp"
    if extension == ".webm":
        return content.startswith(b"\x1a\x45\xdf\xa3")
    return False


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    try:
        password_salt, password_hash = load_or_create_password()
        initialize_database()
        server = AdminServer((HOST, PORT), password_salt, password_hash)
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as error:
        print(f"Не удалось запустить админ-панель: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    print(f"Админ-панель FLASH BANG: http://{HOST}:{PORT}", flush=True)
    print("Сервер доступен только на этом компьютере. Для остановки нажми Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
