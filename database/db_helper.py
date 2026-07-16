import sqlite3

def connect():
    return sqlite3.connect("database/app.db")


def create_table():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            time TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_log(url, result):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO logs (url, result, time) VALUES (?, ?, datetime('now'))",
        (url, result)
    )

    conn.commit()
    conn.close()


def fetch_logs():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    data = cursor.fetchall()

    conn.close()
    return data