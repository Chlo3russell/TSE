import sqlite3

# Create/connect to a database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create a simple table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE
    )
''')

# Single insert
cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", ('John', 'john@email.com'))

# Multiple inserts
users = [('Alice', 'alice@email.com'), ('Bob', 'bob@email.com')]
cursor.executemany("INSERT INTO users (name, email) VALUES (?, ?)", users)

# Always commit changes
conn.commit()