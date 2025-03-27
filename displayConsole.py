from flask import Flask, render_template
import mysql.connector

app = Flask(__name__)

# Connect to MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Replace with your MySQL username
    password="password",  # Replace with your MySQL password
    database="traffic_monitoring"
)
cursor = db.cursor(dictionary=True)

@app.route("/")
def index():
    """
    Fetch data from the database and display it on the web page.
    """
    # Fetch data from Location table
    cursor.execute("SELECT * FROM Location")
    locations = cursor.fetchall()

    # Fetch data from IP_Traffic table
    cursor.execute("SELECT * FROM IP_Traffic")
    ip_traffic = cursor.fetchall()

    # Fetch data from Flagged_Metrics table
    cursor.execute("SELECT * FROM Flagged_Metrics")
    flagged_metrics = cursor.fetchall()

    return render_template("template.html", locations=locations, ip_traffic=ip_traffic, flagged_metrics=flagged_metrics)

if __name__ == "__main__":
    app.run(debug=True)