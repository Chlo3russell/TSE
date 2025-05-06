from datetime import datetime
import os
import time
import subprocess
import threading
import sqlite3
import ipaddress

from flask import Flask, Response, jsonify, render_template, redirect, stream_with_context, url_for, request, flash, g
from firewallMonitor import Firewall
from Database.databaseScript import Database

from flask import session
from functools import wraps
from flask_cors import CORS

# Import attack classes
from Attacks.synack import SYNFlood
from Attacks.httpflood import HTTPFlood
from Attacks.UDPFlood import UDPFloodAttack

# Store attack instances
attack_instances = {
    'syn': None,
    'http': None,
    'udp': None
}

# Path to central log file
LOG_FILE = 'logs/app.log'

app = Flask(__name__)
CORS(app)  # Add CORS support
app.secret_key = "defenceBranch"

def get_firewall():
    '''
    Helper function to get the firewall
    '''
    if 'firewall' not in g:
        g.firewall = Firewall()
    return g.firewall

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/logout")
def logout():
    session.pop('user_id', None)
     # Return JSON response instead of redirect
    return jsonify({"message": "success"}) 



@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            if not request.is_json:
                return jsonify({"message": "Missing JSON"}), 400
                
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            # Check against the Node.js stored credentials
            if username == 'testuser' and password == 'password123':
                session['user_id'] = username
                return jsonify({"message": "success"})
            
            return jsonify({"message": "Invalid username or password"}), 401
            
        except Exception as e:
            print(f"Login error: {str(e)}")  # Debug logging
            return jsonify({"message": "Server error"}), 500
            
    return render_template('login/login.html')

@app.teardown_appcontext
def close_firewall(exception):
    '''
    Helper function to close the firewall connection
    '''
    fw = g.pop('firewall', None)
    if fw is not None:
        fw.db._conn.close()  # Close the db connection if firewall has one

def get_db():
    '''
    Helper function to get the db connection
    '''
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = Database()
    return db

@app.teardown_appcontext
def close_connection(exception):
    '''
    Helper function to close the db connection
    '''
    db = getattr(g, '_database', None)
    if db is not None:
        db._conn.close()

def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

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
        db._c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'")
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
@login_required
def defense_settings():
    '''
    Get block or unblock actions from the page.
    '''
    try:
        db = get_db()
        firewall = get_firewall()
    
        if request.method == 'POST':
            ip_address = request.form.get('ip_address')
            action = request.form.get('action')
            protocol = request.form.get('protocol')
            port = request.form.get('port')
            per_second = request.form.get('per_second')
            burst_limit = request.form.get('burst_limit') 

            # Block/Unblock 
            if ip_address: 
                try:
                    if is_valid_ip(ip_address):
                        if action == 'block': 
                            if not firewall.block_ip(ip_address, reason="Blocked manually by admin"):
                                flash("Failed to block IP", "error")
                            else:
                                flash("IP successfully blocked", "success")

                        elif action == 'unblock': 
                            if not firewall.unblock_ip(ip_address):
                                flash("Failed to unblock IP", "error")
                            else:
                                flash("IP successfully unblocked", "success")
                    else:
                        flash("Invalid IP address format", "error")
                        return redirect(url_for('defense_settings'))
                except Exception as e:
                    flash(f"Unexpected error: {e}", "error")
                    return redirect(url_for('defense_settings'))
                
            elif action in ['add_rate_limit', 'remove_rate_limit'] and protocol:
                if not per_second or not burst_limit:
                    flash("Per second and Burst limit values are required", "error")
                    return redirect(url_for('defense_settings'))
                try:
                    per_second = int(per_second)
                    burst_limit = int(burst_limit)
                    port = int(port) if port else None

                    if per_second <=0 or burst_limit <=0:
                        flash("Rate limits must be positive integers", "error")
                        return redirect(url_for('defense_settings'))

                    if action == 'add_rate_limit':
                        if firewall.add_rate_limit(protocol, port, per_second, burst_limit):
                            flash("Rate limit added", "success")
                        else:
                            flash("Failed to add rate limit", "error")

                    elif action == 'remove_rate_limit':
                        if firewall.remove_rate_limit(protocol, port, per_second, burst_limit):
                            flash("Rate limit removed", "success")
                        else:
                            flash("Failed to remove rate limit", "error")
                except ValueError:
                    flash(f"Rate limit values must be integers", "error")
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
    return render_template("log_viewer.html")

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
@login_required
def attack_simulation():
    """
    Render the attack simulation page.
    """
    return render_template("attack_simulation.html")

@app.route("/syn_attack", methods=['POST'])
@login_required
def syn_attack():
    try:
        attack_instances['syn'] = SYNFlood()
        threading.Thread(target=attack_instances['syn'].startAttack).start()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Failed to start SYN attack: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/http_attack", methods=['POST'])
@login_required
def http_attack():
    try:
        attack_instances['http'] = HTTPFlood()
        threading.Thread(target=attack_instances['http'].startAttack).start()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Failed to start HTTP attack: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/udp_attack", methods=['POST'])
@login_required
def udp_attack():
    try:
        attack_instances['udp'] = UDPFloodAttack('localhost', 5000)
        threading.Thread(target=attack_instances['udp'].start).start()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Failed to start UDP attack: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/stop_syn_attack", methods=['POST'])
@login_required
def stop_syn_attack():
    if attack_instances['syn']:
        attack_instances['syn'].stopAttack()
        attack_instances['syn'] = None
    return jsonify({"success": True})

@app.route("/stop_http_attack", methods=['POST'])
@login_required
def stop_http_attack():
    if attack_instances['http']:
        attack_instances['http'].active = False
        attack_instances['http'] = None
    return jsonify({"success": True})

@app.route("/stop_udp_attack", methods=['POST'])
@login_required
def stop_udp_attack():
    if attack_instances['udp']:
        # UDP attack stops naturally after duration
        attack_instances['udp'] = None
    return jsonify({"success": True})

if __name__ == "__main__":
    if not os.path.exists("logs"):
        os.makedirs("logs")
    app.run(debug=True, port=5001)