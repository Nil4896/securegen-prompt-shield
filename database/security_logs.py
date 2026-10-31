import json
import sqlite3
from datetime import datetime,timezone

DB_PATH = "securegen_events.db"

def initialize_database():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, stage TEXT NOT NULL, decision TEXT NOT NULL, risk TEXT NOT NULL, categories TEXT NOT NULL, classifier_label TEXT NOT NULL)")

def log_event(stage,decision,risk,categories,classifier_label="not_run"):
    safe_categories = [str(x)[:50] for x in categories[:10]]
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT INTO events (created_at,stage,decision,risk,categories,classifier_label) VALUES (?,?,?,?,?,?)",
                   (datetime.now(timezone.utc).isoformat(),stage,decision,risk,json.dumps(safe_categories),str(classifier_label)[:40]))

def recent_events(limit=100):
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("SELECT created_at,stage,decision,risk,categories,classifier_label FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [{"Time (UTC)":r[0],"Stage":r[1],"Decision":r[2],"Risk":r[3],"Detected categories":r[4],"Classifier":r[5]} for r in rows]

def event_counts():
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute(
            "SELECT LOWER(TRIM(decision)), COUNT(*) FROM events GROUP BY LOWER(TRIM(decision))"
        ).fetchall()

    counts = dict(rows)

    return {
        "total": sum(counts.values()),
        "blocked": counts.get("block", 0) + counts.get("blocked", 0),
        "review": counts.get("review", 0),
        "redacted": counts.get("redacted", 0)
    }

def clear_events():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("DELETE FROM events")
