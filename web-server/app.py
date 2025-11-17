import time
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import datetime
import webbrowser
import threading

# --- Initialization ---
app = Flask(__name__)
# CORRECTED: Set the database URI to use SQLite (will create site.db file)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Model (Measurement Table) ---
class Measurement(db.Model):
    # Sequence ID for X-axis on the graph
    id = db.Column(db.Integer, primary_key=True) 
    
    # Data from ESP32
    bssid = db.Column(db.String(17), nullable=False)
    ssid = db.Column(db.String(120), nullable=False)
    rssi = db.Column(db.Integer, nullable=False)
    channel = db.Column(db.Integer, nullable=True)
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Measurement('{self.id}', '{self.ssid}', '{self.rssi}')"

# Function to create DB tables
def create_tables():
    with app.app_context():
        db.create_all()

# Function to automatically open the browser after a short delay
def open_browser():
    # Wait briefly for the server to start listening
    time.sleep(1) 
    # Open the local address and port 5001
    webbrowser.open_new("http://127.0.0.1:5001/")

# --- Server Routes ---

@app.route("/")
def home():
    # Renders the main dashboard page
    return render_template('index.html', title='Карта сигнала Wi-Fi (Линейный график)')

# API endpoint for POST requests from ESP32
@app.route("/api/measurement", methods=['POST'])
def receive_measurement():
    if request.is_json:
        try:
            data = request.get_json()
            scan_results = data.get('scan_results', [])
            
            # Save all received scan results to the database
            for measurement in scan_results:
                new_entry = Measurement(
                    bssid=measurement.get('bssid'),
                    ssid=measurement.get('ssid'),
                    rssi=measurement.get('rssi'),
                    channel=measurement.get('channel')
                )
                db.session.add(new_entry)
            
            db.session.commit()
            print(f"Saved {len(scan_results)} new measurements.")
            
            return jsonify({"message": "Data successfully received and saved"}), 200
        
        except Exception as e:
            db.session.rollback()
            print(f"Database error: {e}")
            return jsonify({"error": "Error saving data to database"}), 500
            
    return jsonify({"error": "Request must be JSON"}), 400

# API endpoint to retrieve data for the chart (GET request from JavaScript)
@app.route("/api/chart_data", methods=['GET'])
def get_chart_data():
    # Filter by SSID if provided
    ssid_filter = request.args.get('ssid')
    
    # Query all measurements, ordered by ID (sequence)
    query = db.session.query(Measurement).order_by(Measurement.id)
    
    if ssid_filter and ssid_filter != 'all':
        query = query.filter(Measurement.ssid == ssid_filter)
        
    measurements = query.all()

    # Process data for Chart.js
    
    processed_data = {}
    
    for m in measurements:
        if m.ssid not in processed_data:
            processed_data[m.ssid] = {'ids': [], 'rssi_values': []}
        
        processed_data[m.ssid]['ids'].append(m.id)
        processed_data[m.ssid]['rssi_values'].append(m.rssi)
        
    # Also collect all unique SSIDs for the filter dropdown
    unique_ssids = db.session.query(Measurement.ssid).distinct().all()
    unique_ssids = [s[0] for s in unique_ssids]

    return jsonify({
        "data": processed_data,
        "ssids": unique_ssids
    }), 200

if __name__ == '__main__':
    create_tables()
    # Start the thread to open the browser
    threading.Thread(target=open_browser).start()
    # Run the server on port 5001, disabling the reloader to prevent duplicate browser tabs
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)