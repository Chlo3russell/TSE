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
    try:
        db = get_db()
    
        if request.method == 'POST':
            ip_address = request.form.get('ip_address')
            action = request.form.get('action')
            protocol = request.form.get('protocol')
            port = request.form.get('port')
            per_second = request.form.get('per_second')
            burst_limit = request.form.get('burst_limit') 

            # Block/Unblock 
            if ip_address: 
                if action == 'block': 
                    if not defense.block_ip(ip_address, reason="Blocked manually by admin"):
                        flash("Failed to block IP", "error")
                elif action == 'unblock': 
                    if not defense.unblock_ip(ip_address):
                        flash("Failed to unblock IP", "error")
            elif action in ['add_rate_limit', 'remove_rate_limit'] and protocol:
                try:
                    per_second = int(per_second)
                    burst_limit = int(burst_limit)
                    port = int(port) if port else None
                    # Validate protocol
                    if action == 'add_rate_limit':
                        defense.add_rate_limit(protocol, port, per_second, burst_limit)
                    elif action == 'remove_rate_limit':
                        defense.remove_rate_limit(protocol, port, per_second, burst_limit)
                except Exception as e:
                    flash(f"Error parsing rate limit values: {e}", "error")
                    return redirect(url_for('defense_settings'))
            return redirect(url_for('defense_settings'))
      
        blocked_ips = db._get_blocked_ips()
        return render_template('defense.html', blocked_ips=blocked_ips)
    except Exception as e:
        flash(f"An error occurred: {e}", "error")
        return redirect(url_for('dashboard'))

@app.route("/api/blocked-ips")
def api_blocked_ips():
    try:
        db = get_db()
        results = db._get_blocked_ips()
        if results:
            output = [{
                'ip_address': row['ip_address'],
                'block_time': row['block_time'],
                'unblock_time': row['unblock_time'],
                'reason': row['reason']
            } for row in results]
            return jsonify(output)
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rate-limits")
def api_rate_limits():
    try:
        db = get_db()
        logs = db._get_rate_limit_actions()
        return jsonify(logs if logs else [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logviewer")
def log_view():
    return render_template("logviewer.html")

@app.route("/logs")  # Single clear route for logs
def stream_logs():
    level = request.args.get('level')
    keyword = request.args.get('keyword')

    def tail_log():
        try:
            with open(LOG_FILE, "r", encoding='utf-8') as file:
                # First read existing content
                lines = file.readlines()
                for line in lines:
                    if level and f" - {level.upper()} -" not in line:
                        continue
                    if keyword and keyword.lower() not in line.lower():
                        continue
                    yield f"data: {line.strip()}\n\n"
                
                # Then watch for new content
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.1) 
                        continue
                    if level and f" - {level.upper()} -" not in line:
                        continue
                    if keyword and keyword.lower() not in line.lower():
                        continue
                    yield f"data: {line.strip()}\n\n"
        except Exception as e:
            print(f"Error in tail_log: {e}")
            
    return Response(
        stream_with_context(tail_log()),
        mimetype="text/event-stream",
        headers={
            'Cache-Control': 'no-cache',
            'Access-Control-Allow-Origin': '*'
        }
    )

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

def get_traffic_data():
    """
    Fetch traffic data from the database.
    """
    try:
        db = get_db()
        db._c.execute("SELECT * FROM traffic_logs")
        traffic_data = [dict(row) for row in db._c.fetchall()]
        return traffic_data
    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
        return []

@app.route("/traffic-logs")
def traffic_log_view():
    traffic_logs = get_traffic_data()
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