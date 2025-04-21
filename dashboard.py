from flask import Flask, render_template, redirect, url_for, request, flash
import sqlite3
from firewallMonitor import Firewall
from database.databaseScript import Database

# Path to central log file
LOG_FILE = 'logs/app.log'

app = Flask(__name__)
app.secret_key = "defenseBranch"

# Connect to existing SQLite database
db = Database()
defense = Firewall()

@app.route("/")
def dashboard():
    """
    Fetch all tables and their data from the SQLite database and display them.
    """
    try:
        # Get list of all tables
        db._c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
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

    blocked_ips = db._conn._get_blocked_ips()
    return render_template('defense.html', blocked_ips=blocked_ips)




if __name__ == "__main__":
    app.run(debug=True)