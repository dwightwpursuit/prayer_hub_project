from flask import Flask, render_template, request

app = Flask(__name__)

# This list will temporarily store our prayer requests
prayer_requests = []

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if request.method == 'POST':
        # Get the data from the form input named 'request_text'
        new_request = request.form['request_text']

        # Add the new request to our list
        prayer_requests.append(new_request)

        # For now, just print it to the console to confirm
        print(f"New prayer request submitted: {new_request}")
        print(f"All current requests: {prayer_requests}")

        # Redirect back to the home page after submission
        return "Prayer request submitted successfully! Check your console."
        # We'll change the return later to be more user-friendly
if __name__ == '__main__':
    app.run(debug=True)