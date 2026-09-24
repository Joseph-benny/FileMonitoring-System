import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from monitoring.watcher import start_monitoring

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

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    
    # Get the risk filter from the URL (default to 'ALL' if none selected)
    selected_risk = request.args.get("risk", "ALL")
    
    conn = get_db()
    
    # Conditional SQL query based on the selected filter
    if selected_risk and selected_risk != "ALL":
        query = "SELECT * FROM alerts WHERE risk_level = ? ORDER BY id DESC LIMIT 50"
        alerts = conn.execute(query, (selected_risk,)).fetchall()
    else:
        query = "SELECT * FROM alerts ORDER BY id DESC LIMIT 50"
        alerts = conn.execute(query).fetchall()
        
    conn.close()
    
    # Fetch statistics for Phase 3 counting
    stats = get_alert_statistics(DATABASE)
    
    return render_template(
        "dashboard.html", 
        alerts=alerts, 
        stats=stats, 
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