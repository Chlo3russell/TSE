from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"Found tables: {tables}")  # Debug print
        
        data = {}
        for table in tables:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            data[table] = [dict(row) for row in rows]  # Convert to dictionary
            print(f"Table {table} has {len(rows)} rows")  # Debug print
            
        conn.close()
        return render_template("template.html", data=data)
        
    except Exception as e:
        print(f"Error: {str(e)}")  # Debug print
        return f"An error occurred: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)