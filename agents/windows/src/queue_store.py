"""Durable bounded queue. Enqueue and bookmark update commit together."""
import json
import sqlite3
from pathlib import Path
class QueueFull(Exception):pass
class QueueStore:
    def __init__(self,path:Path,max_events=10000,max_bytes=20*1024*1024):
        self.max_events=max_events;self.max_bytes=max_bytes
        self.db=sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY,event_key TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,size INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);')
    def checkpoint(self):
        row=self.db.execute("SELECT value FROM state WHERE key='bookmark'").fetchone()
        return row[0] if row else None
    def enqueue(self,event,bookmark):
        payload=json.dumps(event,separators=(',',':')) if event else None
        size=len(payload.encode()) if payload else 0
        with self.db:
            exists=self.db.execute('SELECT 1 FROM queue WHERE event_key=?',(event['eventKey'],)).fetchone() if event else None
            if event and not exists:
                count,total=self.db.execute('SELECT count(*),coalesce(sum(size),0) FROM queue').fetchone()
                if count>=self.max_events or total+size>self.max_bytes:
                    raise QueueFull('Local queue capacity reached; collection paused without advancing bookmark')
                self.db.execute('INSERT INTO queue(event_key,payload,size) VALUES(?,?,?)',(event['eventKey'],payload,size))
            self.db.execute("INSERT INTO state(key,value) VALUES('bookmark',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(bookmark,))
    def batch(self,limit=100):
        return [(row[0],json.loads(row[1])) for row in self.db.execute('SELECT id,payload FROM queue ORDER BY id LIMIT ?',(limit,))]
    def acknowledge(self,ids):
        with self.db:self.db.executemany('DELETE FROM queue WHERE id=?',[(i,) for i in ids])
        if self.depth()==0:self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    def depth(self):return self.db.execute('SELECT count(*) FROM queue').fetchone()[0]
    def close(self):self.db.close()
