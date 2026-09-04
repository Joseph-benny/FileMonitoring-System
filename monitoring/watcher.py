import time
from datetime import datetime
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, db_path):
        self.db_path = db_path

    def log_event(self, event_type, file_path):
        # Ignore temp or hidden files to reduce noise
        if ".__" in file_path or file_path.endswith(".tmp"):
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] ALERT: {event_type} -> {file_path}")
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO alerts (timestamp, event_type, file_path) VALUES (?, ?, ?)",
                (timestamp, event_type, file_path)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database write error: {e}")

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("CREATED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("DELETED", event.src_path)

def start_monitoring(path_to_watch, db_path):
    event_handler = RansomwareDetectionHandler(db_path)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"[*] File Integrity Monitor started. Watching directory: {path_to_watch}")