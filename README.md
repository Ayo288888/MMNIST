
#Intrusion Detection System (IDS) Web Application
An intuitive, Flask-based web application that integrates a Machine Learning classifier to detect network intrusions and malicious activities in real-time. The system scales numerical features using a pre-trained data standardizer and predicts attack names and types via a Decision Tree model. Validated threats are logged into a local SQLite database for statistical review and system logging.

🚀 Features
User Authentication System: Secure registration and login mechanics equipped with salted password hashing using werkzeug.security. Includes a built-in endpoint for password updates.

Real-time Attack Classification: Predicts 22 specific types of network attacks (e.g., neptune, smurf, satan, rootkit) across multiple severity tiers (None, Medium, High, Critical) using a Decision Tree model.

Custom Simulation Testing: Allows authenticated users to input specific parameters (such as Source Bytes, Destination Bytes, Duration, and Connection Counts) via an interface to evaluate data against the ML model.

Live Metrics Dashboard: Aggregates background metrics dynamically, showing data ranges for the last 3, 6, or 12 months, including calculating high-severity instances and finding the most common threat vectors.

Comprehensive Log Tracking: Contains endpoints to aggregate combined system tracks—such as user login histories and captured security incidents.

🛠️ Technology Stack
Backend Framework: Flask 3.1.3, Werkzeug 3.1.8

Machine Learning / Data Processing: Scikit-Learn, NumPy, Joblib, Pandas

Database Engine: SQLite3 (Standard Python library)

Production Server: Gunicorn

📋 Prerequisites & Infrastructure Requirements
The application requires specific serialization components to successfully drive the Machine Learning pipeline:

decision_tree_model.pkl – The saved state of the trained Decision Tree classifier.

data_standardizer.pkl – The trained preprocessing object used to transform input metrics.

If these files are missing at startup, the system gracefully prints a warning and operates strictly as a baseline portal without live inference capabilities.

⚙️ Installation & Setup
Clone the Repository

Bash
git clone <repository-url>
cd intrusion_Detection_System
Set Up a Virtual Environment (Recommended)

Bash
python -bin/python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
Install Dependencies

Bash
pip install -r requirements.txt
Verify Required ML Pickles
Ensure your pre-trained decision_tree_model.pkl and data_standardizer.pkl files are placed directly in the project root folder.

Initialize the Database
The application automatically generates the required relational environment (users.db) with users and attacks schemas upon its initial launch.

💻 Running the Application
Development Server
Run the default Flask developer environment:

Bash
python app.py
The interface will be accessible locally via your web browser at http://127.0.0.1:5000/.

Production Deployment
For deployment environments, invoke the WSGI HTTP server:

Bash
gunicorn app:app
📂 Project Structure Overview
Plaintext
├── app.py                     # Primary Flask application containing core routing and business logic
├── requirements.txt           # Explicit pinning of framework and utility versions
├── users.db                   # Main SQLite database containing system/user metrics (auto-generated)
├── decision_tree_model.pkl    # Serialized Decision Tree model state
├── data_standardizer.pkl      # Serialized Scikit-Learn standardizer state
├── template/                  # UI Presentation Layer (HTML Layouts)
│   ├── landing.html           # Initial entry splash screen
│   ├── index.html             # User login validation view
│   ├── register.html          # Registration form view
│   ├── dashboard.html         # User-authorized central hub
│   ├── attack.html            # Feature selection simulation panel
│   ├── alerts.html            # Real-time incident logs tracking window
│   ├── statistics.html        # Attack telemetry charts overview
│   └── systemlogs.html        # Comprehensive administrative audit trail
└── static/                    # Asset repository (CSS Stylesheets, Client Scripts, Images)
🔐 API and Routing Endpoints
Authorization & System Settings
GET / - Renders the primary landing splash screen.

GET, POST /login - Manages user authentication sessions.

POST /update_password - Modifies password structures for authenticated sessions.

GET, POST /register - Inserts new administrative credentials safely into the DB.

GET /logout - Clears active memory cookies and redirects out.

Metrics & Interactive Diagnostics
GET /dashboard - Core view accessible only to logged-in users.

GET /detect_attack - Renders a form with the 10 required features to manually evaluate a request.

POST /predict - Accepts structural parameters asynchronously, checks them against the ML framework, logs malicious profiles, and yields JSON outcomes.

GET /get_attack_stats - Provides structured interval-based summaries (3, 6, 12 months) for real-time telemetry rendering.

GET /get_system_logs - Pulls historical audit points reflecting administrative logins alongside structural security observations.

GET /get_alerts - Queries the final 50 recorded threats parsed out via database indexes.
