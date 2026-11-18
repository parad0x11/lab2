# Учебное УЯЗВИМОЕ веб-приложение (только стандартные модули Python).
# Уязвимость 1: SQL-инъекция          (OWASP A03:2021 Injection)        -> /login
# Уязвимость 2: Path Traversal         (OWASP A01:2021 Broken Access Control) -> /file
# Запуск: python3 app.py   ->  http://127.0.0.1:8000

import os
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(BASE, "files")
DB = os.path.join(BASE, "users.db")


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (login TEXT, password TEXT)")
    con.execute("DELETE FROM users")
    con.execute("INSERT INTO users VALUES ('admin', 'S3cr3t_P@ss_2026')")
    con.commit()
    con.close()


class Handler(BaseHTTPRequestHandler):
    def send(self, code, text):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)

        if url.path == "/login":
            login = q.get("login", [""])[0]
            password = q.get("password", [""])[0]
            con = sqlite3.connect(DB)
            # УЯЗВИМОСТЬ: пользовательский ввод вставляется прямо в SQL-запрос
            sql = f"SELECT login FROM users WHERE login = '{login}' AND password = '{password}'"
            row = con.execute(sql).fetchone()
            con.close()
            if row:
                self.send(200, f"Добро пожаловать, {row[0]}!")
            else:
                self.send(403, "Неверный логин или пароль")

        elif url.path == "/file":
            name = q.get("name", [""])[0]
            # УЯЗВИМОСТЬ: имя файла не проверяется, можно выйти из папки files через ../
            path = os.path.join(FILES, name)
            try:
                with open(path, encoding="utf-8") as f:
                    self.send(200, f.read())
            except OSError:
                self.send(404, "Файл не найден")

        else:
            self.send(200, "Эндпоинты:\n"
                           "  /login?login=...&password=...\n"
                           "  /file?name=readme.txt\n")


if __name__ == "__main__":
    init_db()
    print("Сервер запущен: http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
