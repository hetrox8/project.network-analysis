from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
from scapy.all import sniff

app = Flask(__name__)
CORS(app)

device_appearance = {
    "192.168.0.3": "AA:BB:CC:DD:EE:FF",
    "101.33.47.206": "AA:BB:CC:DD:EE:00"
}

blacklist = []
whitelist = []
sniffing_status = {"status": False}

@app.route('/')
def index():
    return "Welcome to the Network Analysis Tool API!"

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/api/devices', methods=['GET'])
def get_devices():
    devices = list(device_appearance.keys())
    return jsonify({"devices": devices})

@app.route('/api/blacklist', methods=['POST'])
def add_to_blacklist():
    data = request.get_json()
    ip = data.get("ip")
    if ip not in blacklist:
        blacklist.append(ip)
    return jsonify({"message": f"{ip} added to blacklist."})

@app.route('/api/whitelist', methods=['POST'])
def add_to_whitelist():
    data = request.get_json()
    ip = data.get("ip")
    if ip not in whitelist:
        whitelist.append(ip)
    return jsonify({"message": f"{ip} added to whitelist."})

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify({"blacklist": blacklist})

@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    return jsonify({"whitelist": whitelist})

# Route to start sniffing packets
@app.route('/api/start-sniffing', methods=['POST'])
def start_sniffing():
    if sniffing_status["status"]:
        return jsonify({"message": "Sniffing is already running."})
    
    sniffing_status["status"] = True
    threading.Thread(target=run_sniffing).start()
    return jsonify({"message": "Packet sniffing started."})

# Function to run sniffing in the background
def run_sniffing():
    sniff(iface="Ethernet", prn=packet_callback, count=20)  # Adjust iface and count as needed
    sniffing_status["status"] = False

# Example packet processing function
def packet_callback(packet):
    print(f"Packet: {packet.summary()}")

if __name__ == '__main__':
    app.run(debug=True)
    