from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)
DATABASE = 'prayer_hub.db'

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # This makes rows behave like dictionaries, allowing access by column name
    return conn

# Function to initialize the database table
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            prayed_for_count INTEGER DEFAULT 0,
            category TEXT,
            is_answered INTEGER DEFAULT 0 -- New column for 'answered' status (0=False, 1=True)
        )
    ''')
    conn.commit()
    conn.close()

# Call this function once when the app starts to ensure the DB and table exist
init_db()

@app.route('/')
def home():
    # Get the 'category' from the URL query parameters (e.g., /?category=Health)
    selected_category = request.args.get('category')

    conn = get_db_connection()

    if selected_category:
        # If a category is selected, filter the prayers by that category
        db_requests = conn.execute(
            'SELECT id, request_text, timestamp, prayed_for_count, category, is_answered FROM requests WHERE category = ? ORDER BY timestamp DESC',
            (selected_category,)
        ).fetchall()
    else:
        # If no category is selected, fetch all prayers
        db_requests = conn.execute(
            'SELECT id, request_text, timestamp, prayed_for_count, category, is_answered FROM requests ORDER BY timestamp DESC'
        ).fetchall()

    # Fetch unique categories from the database for the filter buttons
    # Only include categories that are not NULL or empty strings
    unique_categories = conn.execute('SELECT DISTINCT category FROM requests WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
    conn.close()

    return render_template('home.html',
                           requests=db_requests,
                           selected_category=selected_category,
                           unique_categories=unique_categories)

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if request.method == 'POST':
        new_request_text = request.form['request_text']
        # Retrieve category; using .get() for optional fields with a default empty string
        category = request.form.get('category', '').strip() # Get category, strip whitespace

        conn = get_db_connection()
        # Insert request_text and category. Store None in DB if category is an empty string.
        conn.execute('INSERT INTO requests (request_text, category) VALUES (?, ?)',
                     (new_request_text, category if category else None))
        conn.commit()
        conn.close()

        print(f"New prayer request submitted and saved to DB: {new_request_text} (Category: {category})")
        return redirect(url_for('home'))

@app.route('/pray_for/<int:request_id>', methods=['POST'])
def increment_pray_count(request_id):
    conn = get_db_connection()
    # Increment the prayed_for_count for the specific request_id
    conn.execute('UPDATE requests SET prayed_for_count = prayed_for_count + 1 WHERE id = ?', (request_id,))
    conn.commit()
    conn.close()
    print(f"Incremented pray count for request ID: {request_id}")
    return redirect(url_for('home'))

@app.route('/mark_as_answered/<int:request_id>', methods=['POST'])
def mark_as_answered(request_id):
    conn = get_db_connection()
    # Set is_answered to 1 (True) for the specific request_id
    conn.execute('UPDATE requests SET is_answered = 1 WHERE id = ?', (request_id,))
    conn.commit()
    conn.close()
    print(f"Prayer request ID: {request_id} marked as answered.")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)