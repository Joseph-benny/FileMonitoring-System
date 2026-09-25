import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from monitoring.watcher import start_monitoring
from datetime import datetime, timedelta
from flask import jsonify

def check_event_frequency(db_path, minutes=5, threshold_limit=10):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Calculate the timestamp threshold (e.g., 5 minutes ago)
    threshold_time = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Count how many events happened since that threshold
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (threshold_time,))
    recent_count = cursor.fetchone()[0]
    conn.close()
    
    # Flag if activity exceeds the limit within the time window
    is_spike = recent_count >= threshold_limit
    
    return {
        "recent_count": recent_count,
        "time_window": minutes,
        "is_activity_spike": is_spike
    }
app = Flask(__name__)
app.secret_key = "super_secret_key_change_in_production"

DATABASE = "database.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_alert_statistics(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Total count of alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    # Count alerts grouped by risk level (High, Medium, Low)
    cursor.execute("SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level")
    risk_breakdown = dict(cursor.fetchall())
    
    # Count alerts grouped by event type (CREATED, MODIFIED, DELETED)
    cursor.execute("SELECT event_type, COUNT(*) FROM alerts GROUP BY event_type")
    type_breakdown = dict(cursor.fetchall())
    
    conn.close()
    
    return {
        "total_alerts": total_alerts,
        "risk_breakdown": risk_breakdown,
        "type_breakdown": type_breakdown
    }

def init_db():
    if not os.path.exists(DATABASE):
        conn = get_db()
        # Create users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        # Create alerts table for file modifications
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                risk_level TEXT NOT NULL
            )
        """)
        # Insert a default admin user (username: admin, password: password123)
        hashed_pw = generate_password_hash("password123")
        conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", hashed_pw))
        conn.commit()
        conn.close()

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
            
    return render_template("login.html", error=error)

def get_alert_trends(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Group alerts by date to track daily activity trends (last 7 days)
    cursor.execute("""
        SELECT DATE(timestamp) as alert_date, COUNT(*) as count 
        FROM alerts 
        GROUP BY DATE(timestamp) 
        ORDER BY alert_date DESC 
        LIMIT 7
    """)
    trends = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return trends

def print_console_table(db_path, limit=10):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Fetch recent alerts
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    alerts = cursor.fetchall()
    conn.close()
    
    if not alerts:
        print("\n[+] No security alerts found in the database.\n")
        return

    # Print table header
    print("\n" + "="*85)
    print(f"{'ID':<5} | {'TIMESTAMP':<20} | {'RISK':<8} | {'EVENT':<10} | {'FILE PATH'}")
    print("="*85)
    
    # Print each row formatted as a table
    for alert in alerts:
        alert_id = str(alert["id"])
        timestamp = str(alert["timestamp"])
        risk = str(alert["risk_level"])
        event = str(alert["event_type"])
        path = str(alert["file_path"])
        
        print(f"{alert_id:<5} | {timestamp:<20} | {risk:<8} | {event:<10} | {path}")
    
    print("="*85 + "\n")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    
    selected_risk = request.args.get("risk", "ALL")
    
    conn = get_db()
    if selected_risk and selected_risk != "ALL":
        query = "SELECT * FROM alerts WHERE risk_level = ? ORDER BY id DESC LIMIT 50"
        alerts = conn.execute(query, (selected_risk,)).fetchall()
    else:
        query = "SELECT * FROM alerts ORDER BY id DESC LIMIT 50"
        alerts = conn.execute(query).fetchall()
    conn.close()
    
    # Gather stats, frequency, and new trend data
    stats = get_alert_statistics(DATABASE)
    frequency = check_event_frequency(DATABASE, minutes=5, threshold_limit=10)
    trends = get_alert_trends(DATABASE)  # <--- New trend summary data
    
    return render_template(
        "dashboard.html", 
        alerts=alerts, 
        stats=stats, 
        frequency=frequency, 
        trends=trends,       # <--- Pass to template
        current_filter=selected_risk, 
        user=session["user"]
    )

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    
    # Target directory to monitor for ransomware-like behavior
    target_dir = os.path.abspath("./monitored_folder")
    os.makedirs(target_dir, exist_ok=True)
    
    # Start file integrity monitoring in a background thread
    start_monitoring(target_dir, DATABASE)
    
    app.run(debug=True, port=5000)

@app.route("/api/metrics")
def api_metrics():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Gather processed data from your functions
    stats = get_alert_statistics(DATABASE)
    frequency = check_event_frequency(DATABASE, minutes=5, threshold_limit=10)
    
    # Return as a structured JSON object
    return jsonify({
        "status": "success",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analytics": {
            "total_alerts": stats["total_alerts"],
            "risk_breakdown": stats["risk_breakdown"],
            "event_breakdown": stats["type_breakdown"]
        },
        "security_status": {
            "is_activity_spike": frequency["is_activity_spike"],
            "recent_events_count": frequency["recent_count"],
            "time_window_minutes": frequency["time_window"]
        }
    })
