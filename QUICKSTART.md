# WiFi IDS - Quick Start Guide

## Prerequisites
- Python 3.8 or higher
- Administrator/Root access (required for packet capture)
- Windows, Linux, or macOS

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python run.py
```

Or alternatively:
```bash
python app.py
```

### 3. Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## Default Configuration

- **Dashboard**: http://localhost:5000
- **API Base**: http://localhost:5000/api/v1
- **Database**: SQLite (wifi_ids.db)
- **Network Interface**: Wi-Fi (Windows) / Default interface (Linux/Mac)

## Key Features to Try

### 1. Start Packet Capture
- Click **"Start Capture"** button on the dashboard
- Watch real-time packet statistics

### 2. View Alerts
- Navigate to **Alerts** page
- See detected threats and suspicious activities
- Acknowledge alerts to mark as reviewed

### 3. Manage Devices
- Go to **Devices** page
- View all connected network devices
- Edit device policies and trust levels

### 4. API Testing

#### Get Devices
```bash
curl http://localhost:5000/api/v1/devices
```

#### Get Alerts
```bash
curl http://localhost:5000/api/v1/alerts
```

#### Start Capture
```bash
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json"
```

#### Acknowledge an Alert
```bash
curl -X POST http://localhost:5000/api/v1/alerts/1/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"acknowledged_by": "admin", "notes": "Reviewed"}'
```

## File Structure

```
wifi_ids/
├── app.py                 # Main Flask application
├── run.py                 # Application launcher
├── config.py              # Configuration settings
├── models.py              # Database models
├── packet_capture.py      # Packet sniffing & filtering
├── protocol_analyzer.py   # HTTP/HTTPS/DNS analysis
├── signature_engine.py    # Signature-based detection
├── anomaly_detection.py   # ML-based anomaly detection
├── alert_manager.py       # Alert creation & reporting
├── device_manager.py      # Device identification & policies
├── api.py                 # REST API endpoints
├── templates/             # HTML templates
│   ├── base.html          # Base template
│   ├── index.html         # Dashboard
│   ├── alerts.html        # Alerts page
│   └── devices.html       # Devices page
├── static/                # Static files (CSS, JS)
├── logs/                  # Log files
│   ├── alerts/            # Alert logs
│   └── forensics/         # Forensic logs
├── models/                # ML models
├── requirements.txt       # Python dependencies
└── README.md              # Full documentation
```

## Configuration Tips

### Change Network Interface
Edit `config.py`:
```python
PACKET_CAPTURE_INTERFACE = 'Ethernet'  # Change to your interface
```

### Adjust Anomaly Detection Sensitivity
Edit `config.py`:
```python
ANOMALY_THRESHOLD = 0.80  # Lower = more sensitive (0.0-1.0)
```

### Database Location
Edit `config.py`:
```python
SQLALCHEMY_DATABASE_URI = 'sqlite:///custom_path/wifi_ids.db'
```

## Troubleshooting

### No Packets Being Captured
- Windows: Make sure you're running as Administrator
- Linux/Mac: Run with `sudo python app.py`
- Check interface name: Windows = "Wi-Fi", Linux = "eth0" or "wlan0"

### Port 5000 Already in Use
```bash
# Kill process on port 5000
# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac:
lsof -ti:5000 | xargs kill -9
```

### Database Lock Error
Delete the database file and restart:
```bash
rm wifi_ids.db
python run.py
```

### Module Not Found
```bash
pip install --upgrade -r requirements.txt
```

## Common Tasks

### Train Anomaly Detection Model
The model trains automatically after 10 packets are captured. To manually retrain:

```python
from app import create_app, anomaly_detector
app = create_app()
with app.app_context():
    packets = [...]  # Your packet data
    anomaly_detector.train(packets)
```

### Add Custom Signature
```python
from signature_engine import SignatureEngine

sig_engine = SignatureEngine()
sig_engine.add_signature('my_sig_1', {
    'pattern': r'malicious_pattern',
    'severity': 'high',
    'category': 'Custom Threat',
    'description': 'My custom detection'
})
```

### Generate Security Report
Visit: `http://localhost:5000/api/report?days=7`

Or via API:
```bash
curl "http://localhost:5000/api/report?device_id=1&days=30"
```

## Next Steps

1. **Configure Policies**: Set up security policies for different device types
2. **Customize Signatures**: Add your organization-specific threat patterns
3. **Monitor Continuously**: Keep dashboard running for real-time monitoring
4. **Review Reports**: Generate weekly/monthly security reports
5. **Tune Detection**: Adjust thresholds based on your environment

## Support & Documentation

For detailed documentation, see: [README.md](README.md)

For API documentation, visit: `http://localhost:5000/api/v1`

## Performance Tips

- On Windows with heavy traffic: Reduce `PACKET_BUFFER_SIZE` in config.py
- Disable unused signatures for better performance
- Run on a dedicated machine for production use
- Monitor CPU/Memory usage with Task Manager

## Security Recommendations

1. Change `SECRET_KEY` in production
2. Use HTTPS for web interface
3. Implement authentication for API
4. Run behind a firewall
5. Regular database backups
6. Monitor log files for errors

---

**Happy Monitoring!** 🔒
