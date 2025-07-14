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

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if request.method == 'POST':
        new_request_text = request.form['request_text']

        conn = get_db_connection()
        conn.execute('INSERT INTO requests (request_text) VALUES (?)', (new_request_text,))
        conn.commit()
        conn.close()

        print(f"New prayer request submitted and saved to DB: {new_request_text}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)