import time
from datetime import datetime
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta

def classify_risk(event_type, file_path, recent_events_count):
    """
    Classifies file events into Low, Medium, or High risk 
    using conditions and simple pattern analysis.
    """
    # High Risk Pattern: Rapid burst of modifications (simulating ransomware mass encryption)
    if recent_events_count >= 5 and event_type in ["MODIFIED", "RENAMED"]:
        return "HIGH"
    
    # Medium Risk Pattern: Deletions or sensitive file extensions
    elif event_type == "DELETED":
        return "MEDIUM"
    elif file_path.endswith((".exe", ".bat", ".sh", ".env")):
        return "MEDIUM"
        
    # Low Risk Pattern: Standard creation or single edits
    else:
        return "LOW"

    

def analyze_recent_activity(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Fetch the last 10 events to check for patterns
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 10")
    events = cursor.fetchall()
    conn.close()
    
    # Loop through events to check frequency patterns
    modification_count = 0
    for event in events:
        if event["event_type"] == "MODIFIED":
            modification_count += 1
            
    # Pattern check: If more than 3 recent modifications exist, flag unusual behavior
    pattern_detected = modification_count >= 3
    
    return {
        "modification_count": modification_count,
        "pattern_detected": pattern_detected,
        "total_analyzed": len(events)
    }

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
                "INSERT INTO alerts (timestamp, event_type, file_path, risk_level) VALUES (?, ?, ?, ?)",
                (timestamp, event_type, file_path,risk_level)
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