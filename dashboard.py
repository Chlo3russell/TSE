from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

# Connect to existing SQLite database
sqlite_db = sqlite3.connect("database.db", check_same_thread=False)
sqlite_db.row_factory = sqlite3.Row
cursor = sqlite_db.cursor()

@app.route("/")
def index():
    """
    Fetch all tables and their data from the SQLite database and display them.
    """
    # Get list of all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row["name"] for row in cursor.fetchall()]
    
    # Retrieve data from each table
    data = {}
    for table in tables:
        cursor.execute(f"SELECT * FROM {table}")
        data[table] = cursor.fetchall()

    return render_template("template.html", data=data)

if __name__ == "__main__":
    app.run(debug=True)