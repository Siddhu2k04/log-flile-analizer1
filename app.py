from flask import Flask, render_template, request
from datetime import datetime
import os

app = Flask(__name__)
os.makedirs("uploads", exist_ok=True)
log_entries = []  # Array for storing parsed log data

# --- Helper ---
def parse_log_line(line):
    try:
        timestamp = datetime.strptime(line.split("]")[0][1:], "%Y-%m-%d %H:%M:%S")
        parts = line.strip().split(":")
        return timestamp, parts[-1].strip(), ":".join(parts[2:-1]).strip(), parts[1].strip()
    except:
        return None, None, None, None

# --- Circular Queue ---
class CircularQueue:
    def __init__(self):
        self.queue, self.front, self.rear, self.size = [None]*1000, 0, -1, 0
    def add(self, value):
        self.rear = (self.rear + 1) % 1000
        self.queue[self.rear] = value
        self.size = min(self.size + 1, 1000)
    def clean_old_entries(self, current_time):
        while self.size and (current_time - self.queue[self.front]).total_seconds() > 60:
            self.front = (self.front + 1) % 1000
            self.size -= 1

@app.route("/", methods=["GET", "POST"])
def upload_log_file():
    global log_entries
    if request.method == "POST":
        uploaded_file = request.files["logfile"]
        if uploaded_file:
            file_path = os.path.join("uploads", uploaded_file.filename)
            uploaded_file.save(file_path)
            with open(file_path) as file:
                log_entries = [parsed for line in file if (parsed := parse_log_line(line))[0]]
            return render_template("analyze.html")
    return render_template("upload.html")

@app.route("/top_active")
def show_top_active_user():
    if not log_entries:
        return '<h3>No data</h3><a href="/analyze" class="back-btn">⬅ Back</a>'
    user_action_count = {}
    for _, user_id, _, _ in log_entries:
        if user_id and user_id.startswith("user"):
            user_action_count[user_id] = user_action_count.get(user_id, 0) + 1
    if not user_action_count:
        return '<h3>No users</h3><a href="/analyze" class="back-btn">⬅ Back</a>'
    top_user = max(user_action_count, key=user_action_count.get)
    return f"<h3>Top Active User:</h3><p>{top_user} → {user_action_count[top_user]} actions</p><br><a href='/analyze' class='back-btn'>⬅ Back</a>"

@app.route("/suspicious")
def detect_suspicious_users():
    if not log_entries:
        return '<h3>No data</h3><a href="/analyze" class="back-btn">⬅ Back</a>'
    user_queues, suspicious_users = {}, set()
    for timestamp, user_id, _, _ in log_entries:
        if not user_id or not user_id.startswith("user"): continue
        if user_id not in user_queues: user_queues[user_id] = CircularQueue()
        user_queue = user_queues[user_id]
        user_queue.add(timestamp)
        user_queue.clean_old_entries(timestamp)
        if user_queue.size >= 100: suspicious_users.add(user_id)
    result = '<br>'.join(suspicious_users) if suspicious_users else 'None'
    return f"<h3>Suspicious Users:</h3>{result}<br><a href='/analyze' class='back-btn'>⬅ Back</a>"

@app.route("/time_range", methods=["POST"])
def filter_by_time_range():
    start_str, end_str = request.form.get("start"), request.form.get("end")
    try:
        start_time, end_time = datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S"), datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S")
    except:
        return '<h3>Invalid time</h3><a href="/analyze" class="back-btn">⬅ Back</a>'
    filtered_logs = [(timestamp, user_id, action) for timestamp, user_id, action, _ in log_entries if start_time <= timestamp <= end_time]
    if not filtered_logs:
        return '<h3>No records</h3><a href="/analyze" class="back-btn">⬅ Back</a>'
    rows = "".join(f"<tr><td>{timestamp}</td><td>{user_id}</td><td>{action}</td></tr>" for timestamp, user_id, action in filtered_logs)
    return f"<table><tr><th>Time</th><th>User</th><th>Action</th></tr>{rows}</table><br><a href='/analyze' class='back-btn'>⬅ Back</a>"

@app.route("/analyze")
def show_analyze_page():
    return render_template("analyze.html")

if __name__ == "__main__":
    app.run(debug=True)
