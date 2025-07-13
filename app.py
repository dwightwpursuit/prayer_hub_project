from flask import Flask, render_template, request, redirect, url_for # ADD redirect, url_for

app = Flask(__name__)

# This list will temporarily store our prayer requests
prayer_requests = []

@app.route('/')
def home():
    # Pass the prayer_requests list to the home.html template
    return render_template('home.html', requests=prayer_requests) # KEY CHANGE HERE

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if request.method == 'POST':
        new_request = request.form['request_text']
        prayer_requests.append(new_request)

        print(f"New prayer request submitted: {new_request}")
        print(f"All current requests: {prayer_requests}")

        # Redirect back to the home page after successful submission
        # This makes for a much smoother user experience
        return redirect(url_for('home')) # KEY CHANGE HERE


if __name__ == '__main__':
    app.run(debug=True)