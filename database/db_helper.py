import sqlite3
import json

DB_PATH = "database/app.db"


def connect():
    return sqlite3.connect(DB_PATH)


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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            verdict TEXT,
            confidence REAL,
            risk_score REAL,
            suspicious_urls TEXT,
            time TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS browser_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            current_url TEXT,
            dl_prediction TEXT,
            verdict TEXT,
            confidence REAL,
            risk_score REAL,
            threat_reasons TEXT,
            time TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vishing_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            transcription TEXT,
            verdict TEXT,
            confidence REAL,
            risk_score REAL,
            reasons TEXT,
            time TEXT DEFAULT (datetime('now'))
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


def insert_email_scan(sender, subject, verdict, confidence, risk_score, suspicious_urls):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO email_scans (sender, subject, verdict, confidence, risk_score, suspicious_urls)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sender, subject, verdict, confidence, risk_score, json.dumps(suspicious_urls))
    )
    conn.commit()
    conn.close()


def insert_browser_scan(current_url, dl_prediction, verdict, confidence, risk_score, threat_reasons):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO browser_scans (current_url, dl_prediction, verdict, confidence, risk_score, threat_reasons)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (current_url, dl_prediction, verdict, confidence, risk_score, json.dumps(threat_reasons))
    )
    conn.commit()
    conn.close()


def insert_vishing_scan(filename, transcription, verdict, confidence, risk_score, reasons):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO vishing_scans (filename, transcription, verdict, confidence, risk_score, reasons)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (filename, transcription, verdict, confidence, risk_score, json.dumps(reasons))
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


def fetch_email_scans(limit=50):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_scans ORDER BY id DESC LIMIT ?", (limit,))
    data = cursor.fetchall()
    conn.close()
    return data


def fetch_browser_scans(limit=50):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM browser_scans ORDER BY id DESC LIMIT ?", (limit,))
    data = cursor.fetchall()
    conn.close()
    return data


def fetch_vishing_scans(limit=50):
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vishing_scans ORDER BY id DESC LIMIT ?", (limit,))
    data = cursor.fetchall()
    conn.close()
    return data
