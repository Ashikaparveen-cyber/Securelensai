"""
Database Layer — MongoDB Atlas via motor (production) with SQLite fallback (dev/local).
Supports collections: users, scans, chat_messages
"""

import os
import json
import asyncio
from datetime import datetime, timezone
import aiosqlite

MONGODB_URI = os.getenv("MONGODB_URI", "").strip()

_motor_client = None
_db = None
_use_mongo = False
_db_initialized = False


async def init_db():
    global _motor_client, _db, _use_mongo, _db_initialized
    if _db_initialized:
        return

    if MONGODB_URI:
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
            _motor_client = AsyncIOMotorClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
            await _motor_client.admin.command('ping')
            _db = _motor_client.get_database()
            _use_mongo = True
            _db_initialized = True
            print("Successfully connected to MongoDB Atlas!")
            return
        except Exception as e:
            print(f"MongoDB connection failed: {e}. Falling back to SQLite database.")
            _use_mongo = False

    # SQLite fallback
    sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
    async with aiosqlite.connect(sqlite_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score INTEGER,
                data TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                operator_id TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        await db.commit()

    _db_initialized = True


async def _ensure_init():
    if not _db_initialized:
        await init_db()


# ── SCAN OPERATIONS ──────────────────────────────────────────────────────────

async def save_scan(scan_id: str, data: dict, user_id: str = "operator"):
    await _ensure_init()
    if _use_mongo and _db is not None:
        doc = {
            "_id": scan_id,
            "scan_id": scan_id,
            "user_id": user_id,
            "url": data.get("url", ""),
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "risk_score": data.get("risk", {}).get("overall_score", 0),
            "vulnerabilities": data.get("risk", {}).get("all_findings", []),
            "data": data,
        }
        await _db.scans.replace_one({"_id": scan_id}, doc, upsert=True)
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
        risk_score = data.get("risk", {}).get("overall_score", 0)
        ts = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        async with aiosqlite.connect(sqlite_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO scans (id, user_id, url, timestamp, risk_score, data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, user_id, data.get("url", ""), ts, risk_score, json.dumps(data)))
            await db.commit()


async def get_scan(scan_id: str) -> dict:
    await _ensure_init()
    if _use_mongo and _db is not None:
        doc = await _db.scans.find_one({"_id": scan_id})
        if doc:
            return doc.get("data", doc)
        return None
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
        async with aiosqlite.connect(sqlite_path) as db:
            async with db.execute("SELECT data FROM scans WHERE id=?", (scan_id,)) as cur:
                row = await cur.fetchone()
                return json.loads(row[0]) if row else None


async def list_scans(user_id: str = "operator", limit: int = 50) -> list:
    await _ensure_init()
    if _use_mongo and _db is not None:
        cursor = _db.scans.find({"user_id": user_id}).sort("timestamp", -1).limit(limit)
        results = []
        async for doc in cursor:
            results.append({
                "scan_id": doc.get("_id", doc.get("scan_id")),
                "url": doc.get("url"),
                "timestamp": doc.get("timestamp"),
                "risk_score": doc.get("risk_score"),
                "risk_level": doc.get("data", {}).get("risk", {}).get("risk_level", "Unknown"),
                "risk_color": doc.get("data", {}).get("risk", {}).get("risk_color", "blue"),
            })
        return results
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
        async with aiosqlite.connect(sqlite_path) as db:
            async with db.execute(
                "SELECT id, url, timestamp, risk_score, data FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit)
            ) as cur:
                rows = await cur.fetchall()
                results = []
                for r in rows:
                    raw_data = json.loads(r[4])
                    results.append({
                        "scan_id": r[0],
                        "url": r[1],
                        "timestamp": r[2],
                        "risk_score": r[3],
                        "risk_level": raw_data.get("risk", {}).get("risk_level", "Unknown"),
                        "risk_color": raw_data.get("risk", {}).get("risk_color", "blue"),
                    })
                return results


# ── CHAT OPERATIONS ──────────────────────────────────────────────────────────

async def save_chat_message(scan_id: str, sender: str, text: str) -> dict:
    await _ensure_init()
    import uuid
    msg_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    msg = {
        "id": msg_id,
        "scan_id": scan_id,
        "sender": sender,
        "text": text,
        "timestamp": ts,
    }
    if _use_mongo and _db is not None:
        doc = {"_id": msg_id, **msg}
        await _db.chat_messages.insert_one(doc)
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
        async with aiosqlite.connect(sqlite_path) as db:
            await db.execute("""
                INSERT INTO chat_messages (id, scan_id, sender, text, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (msg_id, scan_id, sender, text, ts))
            await db.commit()
    return msg


async def get_chat_history(scan_id: str) -> list:
    await _ensure_init()
    if _use_mongo and _db is not None:
        cursor = _db.chat_messages.find({"scan_id": scan_id}).sort("timestamp", 1)
        results = []
        async for doc in cursor:
            results.append({
                "id": doc.get("_id", doc.get("id")),
                "scan_id": doc.get("scan_id"),
                "sender": doc.get("sender"),
                "text": doc.get("text"),
                "timestamp": doc.get("timestamp"),
            })
        return results
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "securelens.db")
        async with aiosqlite.connect(sqlite_path) as db:
            async with db.execute(
                "SELECT id, scan_id, sender, text, timestamp FROM chat_messages WHERE scan_id=? ORDER BY timestamp ASC",
                (scan_id,)
            ) as cur:
                rows = await cur.fetchall()
                return [
                    {"id": r[0], "scan_id": r[1], "sender": r[2], "text": r[3], "timestamp": r[4]}
                    for r in rows
                ]
