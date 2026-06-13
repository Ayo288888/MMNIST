from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import joblib

# Initialize Flask app correctly (only once)
app = Flask(__name__, template_folder="template")
app.secret_key = "super_secret_key"

# ===== MODEL SETUP =====
decision_tree_model = None
data_standardizer = None
reverse_attack_mapping = None

def load_model():
    global decision_tree_model, data_standardizer, reverse_attack_mapping
    try:
        decision_tree_model = joblib.load('decision_tree_model.pkl')
        data_standardizer = joblib.load('data_standardizer.pkl')
        
        # Mapping each attack type to a number
        attack_mapping = {
            'normal': 0, 'neptune': 1, 'warezclient': 2, 'ipsweep': 3, 'portsweep': 4, 'teardrop': 5,
            'nmap': 6, 'satan': 7, 'smurf': 8, 'pod': 9, 'back': 10, 'guess_passwd': 11, 'ftp_write': 12,
            'multihop': 13, 'rootkit': 14, 'buffer_overflow': 15, 'imap': 16, 'warezmaster': 17, 'phf': 18,
            'land': 19, 'loadmodule': 20, 'spy': 21, 'perl': 22
        }
        reverse_attack_mapping = {v: k for k, v in attack_mapping.items()}
        print("Model loaded successfully")
    except Exception as e:
        print(f"Error loading model: {e}")

# mapping attack types to severity levels
# This mapping is based on the severity of the attack type
severity_mapping = {
    'normal': 'None',
    'neptune': 'High',
    'warezclient': 'Medium',
    'ipsweep': 'Medium',
    'portsweep': 'Medium',
    'teardrop': 'High',
    'nmap': 'High',
    'satan': 'High',
    'smurf': 'Critical',
    'pod': 'High',
    'back': 'High',
    'guess_passwd': 'Medium',
    'ftp_write': 'Medium',
    'multihop': 'High',
    'rootkit': 'Critical',
    'buffer_overflow': 'Critical',
    'imap': 'Medium',
    'warezmaster': 'High',
    'phf': 'Medium',
    'land': 'High',
    'loadmodule': 'Critical',
    'spy': 'High',
    'perl': 'High'
}


# Load model at app startup
try:
    load_model()
    print("Model loaded successfully!")
except Exception as e:
    print(f"Warning: Could not load model: {e}")
    print("App will run without ML prediction capabilities")

def predict_attack_decision_tree(input_data):
    if decision_tree_model is None or data_standardizer is None:
        return "Model Not Loaded", "unknown"
    input_data_scaled = data_standardizer.transform(input_data)
    prediction = decision_tree_model.predict(input_data_scaled)[0]
    attack_name = reverse_attack_mapping.get(prediction, "Unknown Attack")
    return attack_name, "malicious" if attack_name != "normal" else "normal"

# ===== DATABASE SETUP =====
def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            attack_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            day_detected DATE NOT NULL,
            time_detected TIME NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        

        conn.commit()
init_db()  # Initialize database

# ===== ROUTES =====
# (Login) Page
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("index.html")

@app.route("/update_password", methods=["POST"])
def update_password():
    if "user_id" not in session:
        return {"status": "error", "message": "You must log in first!"}, 403

    current_password = request.json.get("currentPassword")
    new_password = request.json.get("newPassword")
    confirm_password = request.json.get("confirmPassword")

    if not current_password or not new_password or not confirm_password:
        return {"status": "error", "message": "All fields are required!"}, 400

    if new_password != confirm_password:
        return {"status": "error", "message": "New password and confirmation do not match!"}, 400

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id=?", (session["user_id"],))
        user = cursor.fetchone()

        if not user or not check_password_hash(user[0], current_password):
            return {"status": "error", "message": "Current password is incorrect!"}, 400

        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, session["user_id"]))
        conn.commit()

    return {"status": "success", "message": "Password updated successfully!"}

# Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect("users.db") as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                               (username, email, hashed_password))
                conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists!", "danger")
    return render_template("register.html")

# Protected Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route('/detect_attack')
def attack():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))

    feature_names = [
        'Source Bytes', 'Destination Bytes', 'Duration', 'Service Count',
        'Connection Count', 'Destination Host Service Count',
        'Destination Host Count', 'Hot', 'Wrong Fragments', 'Service'
    ]

    feature_options = {
        'Source Bytes': [
            ('0 bytes (No data)', 0), ('105 bytes', 105), ('147 bytes', 147),
            ('232 bytes', 232), ('480 bytes', 480), ('1,032 bytes', 1032),
            ('5,450 bytes', 5450), ('10,000 bytes', 10000),
            ('50,000 bytes', 50000), ('100,000 bytes', 100000),
            ('500,000 bytes', 500000), ('1,000,000 bytes', 1000000),
        ],
        'Destination Bytes': [
            ('0 bytes (No data)', 0), ('146 bytes', 146), ('248 bytes', 248),
            ('1,000 bytes', 1000), ('5,000 bytes', 5000), ('15,000 bytes', 15000),
            ('50,000 bytes', 50000), ('100,000 bytes', 100000),
            ('500,000 bytes', 500000),
        ],
        'Duration': [
            ('0 sec', 0), ('1 sec', 1), ('2 sec', 2), ('5 sec', 5),
            ('10 sec', 10), ('20 sec', 20), ('30 sec', 30), ('60 sec', 60),
            ('120 sec', 120), ('300 sec', 300), ('600 sec', 600),
            ('1800 sec', 1800), ('5000 sec', 5000),
        ],
        'Service Count': [
            ('1', 1), ('2', 2), ('5', 5), ('10', 10), ('20', 20),
            ('50', 50), ('100', 100), ('200', 200), ('511', 511),
        ],
        'Connection Count': [
            ('1', 1), ('2', 2), ('5', 5), ('10', 10), ('20', 20),
            ('50', 50), ('100', 100), ('200', 200), ('511', 511),
        ],
        'Destination Host Service Count': [
            ('0', 0), ('1', 1), ('5', 5), ('10', 10), ('25', 25),
            ('50', 50), ('100', 100), ('200', 200), ('255', 255),
        ],
        'Destination Host Count': [
            ('1', 1), ('5', 5), ('10', 10), ('25', 25), ('50', 50),
            ('100', 100), ('200', 200), ('255', 255),
        ],
        'Hot': [
            ('0 — No hot indicators', 0), ('1', 1), ('2', 2), ('3', 3),
            ('5', 5), ('10', 10), ('20', 20), ('30', 30),
        ],
        'Wrong Fragments': [
            ('0 — None', 0), ('1', 1), ('2', 2), ('3', 3),
        ],
        'Service': [
            ('IRC', 0), ('X11', 1), ('Z39_50', 2), ('AOL', 3), ('Auth', 4),
            ('BGP', 5), ('Courier', 6), ('CSNET-NS', 7), ('CTF', 8),
            ('Daytime', 9), ('Discard', 10), ('Domain', 11), ('Domain-U', 12),
            ('Echo', 13), ('ECO-I', 14), ('ECR-I', 15), ('EFS', 16),
            ('Exec', 17), ('Finger', 18), ('FTP', 19), ('FTP-Data', 20),
            ('Gopher', 21), ('Harvest', 22), ('Hostnames', 23), ('HTTP', 24),
            ('HTTP-2784', 25), ('HTTPS (443)', 26), ('HTTP-8001', 27),
            ('IMAP4', 28), ('ISO-TSAP', 29), ('KLogin', 30), ('KShell', 31),
            ('LDAP', 32), ('Link', 33), ('Login', 34), ('MTP', 35),
            ('Name', 36), ('NetBIOS-DGM', 37), ('NetBIOS-NS', 38),
            ('NetBIOS-SSN', 39), ('NetStat', 40), ('NNSP', 41), ('NNTP', 42),
            ('NTP-U', 43), ('Other', 44), ('PM-Dump', 45), ('POP-2', 46),
            ('POP-3', 47), ('Printer', 48), ('Private', 49), ('Red-I', 50),
            ('Remote-Job', 51), ('RJE', 52), ('Shell', 53), ('SMTP', 54),
            ('SQL-Net', 55), ('SSH', 56), ('SunRPC', 57), ('Supdup', 58),
            ('Systat', 59), ('Telnet', 60), ('TFTP-U', 61), ('Tim-I', 62),
            ('Time', 63), ('URH-I', 64), ('URP-I', 65), ('UUCP', 66),
            ('UUCP-Path', 67), ('VMNet', 68), ('Whois', 69),
        ],
    }

    return render_template('attack.html', feature_names=feature_names, feature_options=feature_options)


# predict route for AJAX call
@app.route('/predict', methods=['POST'])
def predict():
    if "user_id" not in session:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
    try:
        # Get feature values from the form
        feature_values = []
        for i in range(1, 11):
            feature_values.append(float(request.form.get(f'feature{i}')))
        
        # Reshape for prediction
        input_data = np.array(feature_values).reshape(1, -1)
        
        # Make prediction
        attack_name, attack_type = predict_attack_decision_tree(input_data)
        
        # Log the attack to database if malicious
        if attack_type == 'malicious':
            now = datetime.now()
            severity = severity_mapping.get(attack_name, "Medium")
            
            with sqlite3.connect("users.db") as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO attacks (attack_type, attack_name, severity, day_detected, time_detected)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    attack_type,
                    attack_name,
                    severity,
                    now.strftime("%Y-%m-%d"),
                    now.strftime("%H:%M:%S")
                ))
                conn.commit()

        return jsonify({
            'success': True,
            'attack_name': attack_name,
            'attack_type': attack_type,
            'severity': severity_mapping.get(attack_name, "Medium"),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })
    

# attack statistics route for AJAX call
@app.route('/get_attack_stats')
def get_attack_stats():
    if "user_id" not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    range_param = request.args.get('range', '3months')
    
    with sqlite3.connect("users.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculate date range
        if range_param == '3months':
            date_filter = "AND timestamp >= date('now', '-3 months')"
        elif range_param == '6months':
            date_filter = "AND timestamp >= date('now', '-6 months')"
        elif range_param == '12months':
            date_filter = "AND timestamp >= date('now', '-12 months')"
        else:
            date_filter = ""
        
        # Get monthly counts
        cursor.execute(f"""
        SELECT strftime('%Y-%m', timestamp) as month, 
               COUNT(*) as count
        FROM attacks
        WHERE 1=1 {date_filter}
        GROUP BY strftime('%Y-%m', timestamp)
        ORDER BY month
        """)
        monthly_data = cursor.fetchall()
        
        # Get statistics
        cursor.execute(f"""
        SELECT 
            COUNT(*) as total_attacks,
            SUM(CASE WHEN severity IN ('High', 'Critical') THEN 1 ELSE 0 END) as high_severity,
            (SELECT attack_name FROM attacks 
             WHERE 1=1 {date_filter}
             GROUP BY attack_name 
             ORDER BY COUNT(*) DESC 
             LIMIT 1) as most_common,
            (SELECT COUNT(*) FROM attacks 
             WHERE timestamp >= date('now', '-1 month')) as last_month
        FROM attacks
        WHERE 1=1 {date_filter}
        """)
        stats = cursor.fetchone()
    
    # Format monthly data
    months = []
    counts = []
    for row in monthly_data:
        months.append(row['month'])
        counts.append(row['count'])
    
    return jsonify({
        'months': months,
        'counts': counts,
        'total_attacks': stats['total_attacks'],
        'high_severity': stats['high_severity'],
        'most_common': stats['most_common'],
        'last_month': stats['last_month']
    })



# Route for security log page
@app.route('/get_system_logs')
def get_system_logs():
    if "user_id" not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        with sqlite3.connect("users.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get combined logs from both tables
            cursor.execute("""
                SELECT 
                    a.timestamp,
                    'attack' as log_type,
                    a.attack_name as description,
                    a.severity,
                    u.username,
                    NULL as activity
                FROM attacks a
                LEFT JOIN users u ON a.id = u.id
                
                UNION ALL
                
                SELECT 
                    datetime(u.id, 'unixepoch') as timestamp,
                    'user' as log_type,
                    'User activity' as description,
                    'Low' as severity,
                    u.username,
                    'Logged in' as activity
                FROM users u
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            
            logs = cursor.fetchall()
            return jsonify([dict(log) for log in logs])
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    





# Route for alerts page
@app.route('/alerts')
def alerts():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template('alerts.html')





# Route to fetch alerts
@app.route('/get_alerts')
def get_alerts():
    if "user_id" not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("users.db") as conn:
        conn.row_factory = sqlite3.Row  # Return dictionaries
        cursor = conn.cursor()
        cursor.execute("""
        SELECT attack_name, severity, day_detected, time_detected 
        FROM attacks 
        ORDER BY timestamp DESC
        LIMIT 50
        """)
        alerts = cursor.fetchall()
    return jsonify([dict(alert) for alert in alerts])




# Route for statistics page
@app.route('/statistics')
def statistics():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template('statistics.html')



# Route for system logs page
@app.route('/security_logs')
def logs():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template('systemlogs.html')

@app.route('/settings')
def settings():
    if "user_id" not in session:
        flash("You must log in first!", "warning")
        return redirect(url_for("login"))
    return render_template('settings.html')




# Logout Route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out Sucessfully", "success")
    return redirect(url_for("login"))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)