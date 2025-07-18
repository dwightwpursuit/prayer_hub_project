from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'prayer_hub.db'
# IMPORTANT: Change this secret key to a long, random, and unique string in a real application!
# You can generate one using `secrets.token_hex(16)` in a Python shell.
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_this_for_security'

PRAYER_TIMEZONE = pytz.timezone('America/New_York')

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
            prayed_for_count INTEGER DEFAULT 0,
            category TEXT,
            is_answered INTEGER DEFAULT 0,
            user_id INTEGER,
            is_anonymous INTEGER DEFAULT 0, -- NEW: 0 for false, 1 for true
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    selected_category = request.args.get('category')
    conn = get_db_connection()

    if selected_category:
        db_requests = conn.execute(
            'SELECT r.id, r.request_text, r.timestamp, r.prayed_for_count, r.category, r.is_answered, r.user_id, r.is_anonymous, u.username FROM requests r LEFT JOIN users u ON r.user_id = u.id WHERE r.category = ? ORDER BY r.timestamp DESC',
            (selected_category,)
        ).fetchall()
    else:
        db_requests = conn.execute(
            'SELECT r.id, r.request_text, r.timestamp, r.prayed_for_count, r.category, r.is_answered, r.user_id, r.is_anonymous, u.username FROM requests r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.timestamp DESC'
        ).fetchall()

    current_utc_time = datetime.now(pytz.utc)
    processed_requests = []

    for req in db_requests:
        request_utc_time = pytz.utc.localize(datetime.strptime(req['timestamp'], '%Y-%m-%d %H:%M:%S'))
        time_difference = current_utc_time - request_utc_time

        formatted_timestamp = ""
        if time_difference < timedelta(minutes=60):
            minutes_ago = int(time_difference.total_seconds() / 60)
            if minutes_ago <= 0:
                formatted_timestamp = "just now"
            elif minutes_ago == 1:
                formatted_timestamp = "1 minute ago"
            else:
                formatted_timestamp = f"{minutes_ago} minutes ago"
        else:
            local_request_time = request_utc_time.astimezone(PRAYER_TIMEZONE)
            formatted_timestamp = local_request_time.strftime('%B %d, %Y at %I:%M %p')

        request_dict = dict(req)
        request_dict['formatted_timestamp'] = formatted_timestamp
        request_dict['is_owner'] = session.get('user_id') == req['user_id']
        processed_requests.append(request_dict)

    unique_categories = conn.execute('SELECT DISTINCT category FROM requests WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
    conn.close()

    return render_template('home.html',
                           requests=processed_requests,
                           selected_category=selected_category,
                           unique_categories=unique_categories,
                           current_user_id=session.get('user_id'))

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if 'user_id' not in session:
        flash('Please log in to submit a prayer request.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_request_text = request.form['request_text']
        category = request.form.get('category', '').strip()
        user_id = session['user_id']
        is_anonymous = 1 if request.form.get('is_anonymous') == 'on' else 0

        conn = get_db_connection()
        conn.execute('INSERT INTO requests (request_text, category, user_id, is_anonymous) VALUES (?, ?, ?, ?)',
                     (new_request_text, category if category else None, user_id, is_anonymous))
        conn.commit()
        conn.close()

        print(f"New prayer request submitted and saved to DB: {new_request_text} (Category: {category}) by user ID: {user_id} (Anonymous: {is_anonymous})")
        flash('Your prayer request has been submitted!', 'success')
        return redirect(url_for('home'))

@app.route('/pray_for/<int:request_id>', methods=['POST'])
def increment_pray_count(request_id):
    conn = get_db_connection()
    conn.execute('UPDATE requests SET prayed_for_count = prayed_for_count + 1 WHERE id = ?', (request_id,))
    conn.commit()
    conn.close()
    flash('Prayer count incremented!', 'info')
    return redirect(url_for('home'))

@app.route('/mark_as_answered/<int:request_id>', methods=['POST'])
def mark_as_answered(request_id):
    if 'user_id' not in session:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Ensure only the owner can mark as answered
    request_entry = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()
    if request_entry and request_entry['user_id'] == session['user_id']:
        conn.execute('UPDATE requests SET is_answered = 1 WHERE id = ?', (request_id,))
        conn.commit()
        flash('Prayer request marked as answered!', 'success')
    else:
        flash('You are not authorized to mark this request as answered.', 'danger')
    conn.close()
    return redirect(url_for('home'))

@app.route('/delete_request/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    if 'user_id' not in session:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Ensure only the owner can delete
    request_entry = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()
    if request_entry and request_entry['user_id'] == session['user_id']:
        conn.execute('DELETE FROM requests WHERE id = ?', (request_id,))
        conn.commit()
        flash('Prayer request deleted successfully!', 'success')
    else:
        flash('You are not authorized to delete this request.', 'danger')
    conn.close()
    return redirect(url_for('home'))

@app.route('/edit_request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    if 'user_id' not in session:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    request_entry = conn.execute('SELECT * FROM requests WHERE id = ?', (request_id,)).fetchone()
    conn.close()

    if request_entry is None:
        flash('Prayer request not found.', 'danger')
        return redirect(url_for('home'))

    # Ensure only the owner can edit
    if request_entry['user_id'] != session['user_id']:
        flash('You are not authorized to edit this request.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # This part is handled by update_request
        pass
    return render_template('edit_request.html', request=request_entry)

@app.route('/update_request/<int:request_id>', methods=['POST'])
def update_request(request_id):
    if 'user_id' not in session:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        updated_text = request.form['request_text']
        updated_category = request.form.get('category', '').strip()
        updated_is_anonymous = 1 if request.form.get('is_anonymous') == 'on' else 0

        conn = get_db_connection()
        # Verify ownership before updating
        request_entry = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()
        if request_entry and request_entry['user_id'] == session['user_id']:
            conn.execute('UPDATE requests SET request_text = ?, category = ?, is_anonymous = ? WHERE id = ?',
                         (updated_text, updated_category if updated_category else None, updated_is_anonymous, request_id))
            conn.commit()
            flash('Prayer request updated successfully!', 'success')
        else:
            flash('You are not authorized to update this request.', 'danger')
        conn.close()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            conn.close()
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, hashed_password))
        conn.commit()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)