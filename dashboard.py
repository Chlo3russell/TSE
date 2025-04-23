from datetime import datetime
import os
import time
from flask import Flask, Response, jsonify, render_template, redirect, stream_with_context, url_for, request, flash, g
import sqlite3
from firewallMonitor import Firewall
from Database.databaseScript import Database
import subprocess
import threading

# Path to central log file
LOG_FILE = 'logs/app.log'

app = Flask(__name__)
app.secret_key = "defenseBranch"

# Initialize database and firewall
defense = Firewall()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = Database()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db._conn.close()

def run_attack(attack_script):
    """
    Helper function to run an attack script in a separate thread.
    """
    def attack_thread():
        subprocess.run(["python", f"attacks/{attack_script}"], check=True)
    threading.Thread(target=attack_thread).start()

@app.route("/")
def dashboard():
    """
    Fetch all tables and their data from the SQLite database and display them.
    """
    try:
        db = get_db()
        # Get list of all tables
        db._c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in db._c.fetchall()]
        
        # Retrieve data from each table
        data = {}
        for table in tables:
            db._c.execute(f"SELECT * FROM {table}")
            data[table] = [dict(row) for row in db._c.fetchall()]
        return render_template('dashboard.html', data=data)
    
    except sqlite3.Error as e:
        return (f"Database error occurred: {e}", 500)

@app.route("/defense-settings", methods=['GET', 'POST'])
def defense_settings():
    '''
    Get block or unblock actions from the page.
    '''
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        action = request.form.get('action')

        if ip_address:
            if action == 'block':
                defense.block_ip(ip_address, reason="Blocked manually by admin")
            elif action == 'unblock':
                defense.unblock_ip(ip_address)
        return redirect(url_for('defense_settings'))

    db = get_db()
    blocked_ips = db._get_blocked_ips()
    return render_template('defense.html', blocked_ips=blocked_ips)

@app.route("/logviewer")
def log_view():
    return render_template("logviewer.html")

@app.route("/output_logs")
def stream_logs():
    level = request.args.get('level')
    keyword = request.args.get('keyword')

    def tail_log():
        with open(LOG_FILE, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                if level and f" - {level.upper()} -" not in line:
                    continue
                if keyword and keyword.lower() not in line.lower():
                    continue
                yield f"data: {line.strip()}\n\n"

    return Response(stream_with_context(tail_log()), mimetype="text/event-stream")

@app.route("/historical-logs")
def get_historical_logs():
    level = request.args.get('level')
    keyword = request.args.get('keyword')
    start = request.args.get('start')
    end = request.args.get('end')

    output_logs = []
    if not os.path.exists(LOG_FILE):
        return jsonify(output_logs)

    with open(LOG_FILE, "r") as file:
        for line in file:
            if level and f" - {level.upper()} -" not in line:
                continue
            if keyword and keyword.lower() not in line.lower():
                continue
            if start or end:
                try:
                    timestamp = datetime.strptime(line.split(" - ")[0], "%Y-%m-%d %H:%M:%S,%f")
                    if start and timestamp < datetime.fromisoformat(start):
                        continue
                    if end and timestamp > datetime.fromisoformat(end):
                        continue
                except Exception:
                    continue
            output_logs.append(line.strip())
    return jsonify(output_logs)

@app.route("/traffic-logs")
def traffic_log_view():
    db = get_db()
    traffic_logs = db._get_traffic_logs()
    return render_template('traffic_logs.html', traffic_logs=traffic_logs)

@app.route("/attack_simulation")
def attack_simulation():
    """
    Render the attack simulation page.
    """
    return render_template("attack_simulation.html")


if __name__ == "__main__":
    if not os.path.exists("logs"):
        os.makedirs("logs")
    with open(LOG_FILE, "a") as file:
        file.write("LOG STREAM OPENED")
    app.run(debug=True, port=5001)