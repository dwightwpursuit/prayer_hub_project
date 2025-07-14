from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)
DATABASE = 'prayer_hub.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            prayed_for_count INTEGER DEFAULT 0  -- NEW COLUMN ADDED HERE
        )
    ''')
    conn.commit()
    conn.close()

init_db() # Ensure the database table is created when the app starts

@app.route('/')
def home():
    conn = get_db_connection()
    # Ensure you select the new 'prayed_for_count' column
    db_requests = conn.execute('SELECT id, request_text, timestamp, prayed_for_count FROM requests ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('home.html', requests=db_requests)

@app.route('/pray_for/<int:request_id>', methods=['POST'])
def increment_pray_count(request_id):
    conn = get_db_connection()
    conn.execute('UPDATE requests SET prayed_for_count = prayed_for_count + 1 WHERE id = ?', (request_id,))
    conn.commit()
    conn.close()
    print(f"Incremented pray count for request ID: {request_id}")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)