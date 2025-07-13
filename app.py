from flask import Flask, render_template, request, redirect, url_for
import sqlite3 # New import

app = Flask(__name__)
DATABASE = 'prayer_hub.db' # New constant

# Function to initialize the database table
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

init_db() # Call this function when the app starts

@app.route('/')
def home():
    # This will be updated in the next part to fetch from the database
    return render_template('home.html', requests=[]) # Temporarily pass empty list


@app.route('/submit_request', methods=['POST'])
def submit_request():
    # This will be updated in the next part to insert into the database
    if request.method == 'POST':
        new_request = request.form['request_text']
        print(f"New prayer request submitted: {new_request}")
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)