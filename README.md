# WiFi IDS - Intrusion Detection System for Web Browsers

A comprehensive Python-based WiFi Intrusion Detection System (IDS) with web-based management interface for monitoring and analyzing network traffic on web browsers.

## Features

### 1. **Packet Capture & Filtering**
- Real-time packet capture on specified network interface
- Configurable protocol filtering (TCP, UDP, ICMP)
- Port-based filtering
- IP address filtering
- Circular buffer with configurable size

### 2. **Protocol Analysis (HTTP/HTTPS Inspection)**
- HTTP header parsing and analysis
- HTTPS/TLS version detection (TLS 1.0, 1.2, 1.3)
- SNI (Server Name Indication) extraction
- DNS query detection and parsing
- Hostname and user-agent extraction
- Cookie detection

### 3. **Signature-Based Detection**
- 10+ pre-configured attack signatures
- SQL Injection detection
- XSS (Cross-Site Scripting) detection
- Command Injection detection
- Directory Traversal detection
- LDAP Injection detection
- XXE (XML External Entity) attack detection
- Malware C2 communication detection
- Suspicious user-agent detection
- Easy-to-add custom signatures

### 4. **Anomaly-Based Detection**
- Autoencoder-based anomaly detection using Isolation Forest
- Feature extraction from packet data
- Configurable anomaly threshold
- Automatic model training and persistence
- Entropy calculation for payload analysis

### 5. **Alerting & Reporting**
- Multi-level severity alerts (Critical, High, Medium, Low)
- Alert acknowledgment system
- Daily forensic logging in JSON format
- Alert history and statistics
- Period-based reporting (daily, weekly, monthly)
- Top threat sources identification

### 6. **Device Identification & Policy Mapping**
- MAC address-based device identification
- Vendor OUI (Organizationally Unique Identifier) lookup
- Automatic device type detection
- Policy level assignment (low, medium, high)
- Trusted device marking
- IP-to-MAC mapping

### 7. **Data Storage & Forensic Logging**
- SQLite database for persistent storage
- Device inventory management
- Alert storage with full context
- Traffic log retention
- Forensic JSON logs with timestamps
- Policy rule storage

### 8. **Integration & API Support**
- RESTful API with full endpoints
- Bearer token authentication
- CORS support for cross-origin requests
- JSON request/response format
- Comprehensive API documentation
- Web UI dashboard

## Installation

### Prerequisites
- Python 3.8+
- Windows/Linux/macOS
- Administrator/Root privileges (for packet capture)

### Setup

1. **Clone/Extract the project:**
```bash
cd c:\Users\naray\OneDrive\Desktop\mini_project
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Initialize the database:**
```bash
python -c "from app import create_app; app = create_app()"
```

## Running the Application

### Start the IDS System

```bash
python app.py
```

The application will start on `http://localhost:5000`

### Web Interface
- Dashboard: `http://localhost:5000/`
- Alerts: `http://localhost:5000/alerts`
- Devices: `http://localhost:5000/devices`
- Traffic: `http://localhost:5000/traffic`
- Policies: `http://localhost:5000/policies`
- Reports: `http://localhost:5000/reports`

## API Endpoints

### Devices
- `GET /api/v1/devices` - List all devices
- `GET /api/v1/devices/<id>` - Get device details
- `PUT /api/v1/devices/<id>` - Update device

### Alerts
- `GET /api/v1/alerts` - List alerts
- `POST /api/v1/alerts/<id>/acknowledge` - Acknowledge alert
- `GET /api/v1/alerts/statistics` - Get alert statistics

### Policies
- `GET /api/v1/policies` - List policies

### Traffic Logs
- `GET /api/v1/traffic-logs` - Get traffic logs

### Capture Control
- `POST /api/capture/start` - Start packet capture
- `POST /api/capture/stop` - Stop packet capture
- `GET /api/capture/status` - Get capture status

### Signatures
- `GET /api/v1/signatures` - List signatures

### Reports
- `GET /api/report` - Generate report

## Database Schema

### Tables
- **devices** - Device inventory
- **alerts** - Alert history
- **traffic_logs** - Network traffic logs
- **policy_rules** - Access control policies
- **signature_detections** - Detected attack signatures
- **anomaly_models** - ML model metadata

## Configuration

Edit `config.py` to customize:

```python
PACKET_CAPTURE_INTERFACE = 'Wi-Fi'  # Change network interface
PACKET_BUFFER_SIZE = 10000           # Buffer size for packets
ANOMALY_THRESHOLD = 0.85             # Anomaly sensitivity
SQLALCHEMY_DATABASE_URI = 'sqlite:///wifi_ids.db'
```

## Usage Examples

### Python API

```python
from packet_capture import PacketCapture
from protocol_analyzer import ProtocolAnalyzer
from signature_engine import SignatureEngine
from anomaly_detection import AnomalyDetector

# Initialize components
pc = PacketCapture(interface='Wi-Fi')
analyzer = ProtocolAnalyzer()
sig_engine = SignatureEngine()
anomaly = AnomalyDetector()

# Start capturing
pc.start()

# Get packets
packets = pc.get_recent_packets(10)

# Analyze
for packet in packets:
    analysis = analyzer.analyze_packet(packet)
    detections = sig_engine.detect(packet)
    anomaly_score = anomaly.predict(packet)
```

### REST API Examples

```bash
# Start capture
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json"

# Get devices
curl http://localhost:5000/api/v1/devices

# Get alerts
curl "http://localhost:5000/api/v1/alerts?severity=critical"

# Acknowledge alert
curl -X POST http://localhost:5000/api/v1/alerts/1/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"acknowledged_by": "admin", "notes": "Investigated"}'

# Get traffic logs
curl "http://localhost:5000/api/v1/traffic-logs?limit=50"

# Generate report
curl "http://localhost:5000/api/report?days=7"
```

## Alert Severity Levels

- **Critical** - Immediate threat detection (SQL Injection, Command Injection)
- **High** - Serious security concern (XSS, Directory Traversal)
- **Medium** - Suspicious activity (Anomalies, Encoded attacks)
- **Low** - Informational alerts (New device, Policy violation)

## Detection Methods

1. **Signature-Based**: Pattern matching against known attacks
2. **Anomaly-Based**: ML model detecting unusual traffic patterns
3. **Protocol Analysis**: HTTP/HTTPS inspection
4. **Device Policy**: Policy rule violations

## Performance

- **Packet Processing**: ~1000+ packets/second
- **Database**: SQLite (suitable for single-instance deployment)
- **Model Training**: Auto-trains with 10+ samples
- **Real-time Analysis**: Sub-second latency

## Security Recommendations

1. Change default SECRET_KEY in production
2. Use HTTPS for web interface
3. Implement authentication
4. Run behind firewall/VPN
5. Regularly update signatures
6. Monitor CPU/Memory usage
7. Implement backup strategy
8. Log all administrative actions

## Troubleshooting

### No packets captured
- Check network interface name (use `ipconfig` on Windows)
- Ensure administrator/root privileges
- Verify firewall settings

### Database errors
- Delete `wifi_ids.db` and restart to reset
- Check file permissions in logs directory

### High CPU usage
- Reduce PACKET_BUFFER_SIZE
- Disable unused signatures
- Increase PACKET_TIMEOUT

## Future Enhancements

- Machine learning model improvements
- Multi-threaded packet processing
- Elasticsearch integration
- Machine-to-machine API authentication
- Custom signature builder UI
- Advanced visualization dashboards
- GeoIP threat mapping
- Automated response actions
- Cloud integration

## License

Proprietary - WiFi IDS System

## Support

For issues and feature requests, please contact the development team.
