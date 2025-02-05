import sqlite3

# Create/connect to a database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create a simple table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ISP (
        ISP_ID INT,
        ISP_Name VARCHAR(100),
        Contact_Information VARCHAR(255)
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS Location (
        Location_ID INTEGER PRIMARY KEY,
        Region VARCHAR(100),
        Country VARCHAR(100),
        City VARCHAR(100)
    )
''')


# Always commit changes
conn.commit()