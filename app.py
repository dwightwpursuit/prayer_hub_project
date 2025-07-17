from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'prayer_hub.db'
# IMPORTANT: Change this secret key to a long, random, and unique string in a real application!
# You can generate one using `os.urandom(24).hex()` in a Python shell.
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_this_for_security'

# Define the timezone for displaying times (e.g., Eastern Time - EDT/EST)
# You can change this to your desired timezone, e.g., 'Europe/London', 'America/Chicago', 'Asia/Kolkata'
PRAYER_TIMEZONE = pytz.timezone('America/New_York')

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # This makes rows behave like dictionaries, allowing access by column name
    return conn

# Function to initialize the database tables
def init_db():
    conn = get_db_connection()
    # Create requests table (or add user_id if it already exists)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            prayed_for_count INTEGER DEFAULT 0,
            category TEXT,
            is_answered INTEGER DEFAULT 0,
            user_id INTEGER, -- NEW: Link to users table
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Call this function once when the app starts to ensure the DB and tables exist
init_db()

@app.route('/')
def home():
    selected_category = request.args.get('category')
    conn = get_db_connection()

    if selected_category:
        db_requests = conn.execute(
            # Join to get username from the users table
            'SELECT r.id, r.request_text, r.timestamp, r.prayed_for_count, r.category, r.is_answered, r.user_id, u.username FROM requests r LEFT JOIN users u ON r.user_id = u.id WHERE r.category = ? ORDER BY r.timestamp DESC',
            (selected_category,)
        ).fetchall()
    else:
        db_requests = conn.execute(
            # Join to get username from the users table
            'SELECT r.id, r.request_text, r.timestamp, r.prayed_for_count, r.category, r.is_answered, r.user_id, u.username FROM requests r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.timestamp DESC'
        ).fetchall()

    current_utc_time = datetime.now(pytz.utc) # Get current time in UTC, timezone-aware
    processed_requests = []

    for req in db_requests:
        # Parse the stored timestamp and make it UTC-aware
        # Assuming SQLite stores 'YYYY-MM-DD HH:MM:SS' without timezone info, it's typically UTC.
        request_utc_time = pytz.utc.localize(datetime.strptime(req['timestamp'], '%Y-%m-%d %H:%M:%S'))

        time_difference = current_utc_time - request_utc_time # Calculation is between two UTC-aware datetimes

        formatted_timestamp = ""
        if time_difference < timedelta(minutes=60): # Less than 1 hour
            minutes_ago = int(time_difference.total_seconds() / 60)
            if minutes_ago <= 0: # Handle cases where it might be 0 or slightly negative due to precision
                formatted_timestamp = "just now"
            elif minutes_ago == 1:
                formatted_timestamp = "1 minute ago"
            else:
                formatted_timestamp = f"{minutes_ago} minutes ago"
        else:
            # Convert the UTC time to the desired local timezone for display
            local_request_time = request_utc_time.astimezone(PRAYER_TIMEZONE)
            # Format to "Month Day, Year at HH:MM AM/PM" (e.g., July 15, 2025 at 08:43 PM)
            formatted_timestamp = local_request_time.strftime('%B %d, %Y at %I:%M %p')

        request_dict = dict(req) # Convert sqlite3.Row to a regular dictionary
        request_dict['formatted_timestamp'] = formatted_timestamp
        # Add a flag to indicate if the current user owns this request for UI purposes
        request_dict['is_owner'] = session.get('user_id') == req['user_id']
        processed_requests.append(request_dict)

    unique_categories = conn.execute('SELECT DISTINCT category FROM requests WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()
    conn.close()

    # Pass the processed requests and current user info to the template
    return render_template('home.html',
                           requests=processed_requests,
                           selected_category=selected_category,
                           unique_categories=unique_categories,
                           current_user_id=session.get('user_id')) # Pass user ID to template for conditional display

@app.route('/submit_request', methods=['POST'])
def submit_request():
    # Ensure user is logged in to submit a request
    if 'user_id' not in session:
        flash('Please log in to submit a prayer request.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_request_text = request.form['request_text']
        category = request.form.get('category', '').strip()
        user_id = session['user_id'] # Get the current user's ID from the session

        conn = get_db_connection()
        conn.execute('INSERT INTO requests (request_text, category, user_id) VALUES (?, ?, ?)',
                     (new_request_text, category if category else None, user_id))
        conn.commit()
        conn.close()

        print(f"New prayer request submitted and saved to DB: {new_request_text} (Category: {category}) by user ID: {user_id}")
        flash('Your prayer request has been submitted!', 'success')
        return redirect(url_for('home'))

@app.route('/pray_for/<int:request_id>', methods=['POST'])
def increment_pray_count(request_id):
    # This action does not require the user to be the owner
    conn = get_db_connection()
    conn.execute('UPDATE requests SET prayed_for_count = prayed_for_count + 1 WHERE id = ?', (request_id,))
    conn.commit()
    conn.close()
    print(f"Incremented pray count for request ID: {request_id}")
    flash('You have prayed for this request!', 'info')
    return redirect(url_for('home'))

@app.route('/mark_as_answered/<int:request_id>', methods=['POST'])
def mark_as_answered(request_id):
    # Authorization check - only owner can mark as answered
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    prayer_request = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()

    if prayer_request and prayer_request['user_id'] == session['user_id']:
        conn.execute('UPDATE requests SET is_answered = 1 WHERE id = ?', (request_id,))
        conn.commit()
        flash('Prayer request marked as answered!', 'success')
        print(f"Prayer request ID: {request_id} marked as answered by owner.")
    else:
        flash('You are not authorized to mark this prayer as answered.', 'danger')
        print(f"Unauthorized attempt to mark prayer ID: {request_id} as answered by user {session.get('user_id')}.")

    conn.close()
    return redirect(url_for('home'))

@app.route('/delete_request/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    # Authorization check - only owner can delete
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    prayer_request = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()

    if prayer_request and prayer_request['user_id'] == session['user_id']:
        conn.execute('DELETE FROM requests WHERE id = ?', (request_id,))
        conn.commit()
        flash('Prayer request deleted!', 'success')
        print(f"Prayer request ID: {request_id} deleted by owner.")
    else:
        flash('You are not authorized to delete this prayer request.', 'danger')
        print(f"Unauthorized attempt to delete prayer ID: {request_id} by user {session.get('user_id')}.")

    conn.close()
    return redirect(url_for('home'))

@app.route('/edit_request/<int:request_id>')
def edit_request(request_id):
    # Authorization check - only owner can edit
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Fetch user_id along with other request details
    request_to_edit = conn.execute('SELECT id, request_text, category, user_id FROM requests WHERE id = ?', (request_id,)).fetchone()
    conn.close()

    if request_to_edit is None:
        return "Prayer request not found!", 404
    
    # Compare the request's user_id with the current session's user_id
    if request_to_edit['user_id'] != session['user_id']:
        flash('You are not authorized to edit this prayer request.', 'danger')
        return redirect(url_for('home'))

    return render_template('edit_request.html', request=request_to_edit)

@app.route('/update_request/<int:request_id>', methods=['POST'])
def update_request(request_id):
    # Authorization check - only owner can update
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Fetch user_id to confirm ownership
    prayer_request = conn.execute('SELECT user_id FROM requests WHERE id = ?', (request_id,)).fetchone()

    if prayer_request and prayer_request['user_id'] == session['user_id']:
        if request.method == 'POST':
            updated_text = request.form['request_text']
            updated_category = request.form.get('category', '').strip()

            conn.execute('UPDATE requests SET request_text = ?, category = ? WHERE id = ?',
                         (updated_text, updated_category if updated_category else None, request_id))
            conn.commit()
            flash('Prayer request updated successfully!', 'success')
            print(f"Prayer request ID: {request_id} updated by owner.")
    else:
        flash('You are not authorized to update this prayer request.', 'danger')
        print(f"Unauthorized attempt to update prayer ID: {request_id} by user {session.get('user_id')}.")

    conn.close()
    return redirect(url_for('home'))

# User Registration Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If a user is already logged in, redirect them home
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # Check if username already exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            conn.close()
            return render_template('register.html')

        hashed_password = generate_password_hash(password) # Hash the password
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, hashed_password))
        conn.commit()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# User Login Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If a user is already logged in, redirect them home
    if 'user_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None) # Remove user_id from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)