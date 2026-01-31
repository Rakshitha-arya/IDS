#!/usr/bin/env python3
from app import create_app
from device_manager import DeviceIdentifier

app = create_app()

with app.app_context():
    device_identifier = DeviceIdentifier()

    # Test hybrid identification
    try:
        # Test with sample data
        device1 = device_identifier.identify_device_by_browser_fingerprint(
            "192.168.1.100",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "example.com"
        )
        print(f"Device 1 created: {device1.id}, fingerprint: {device1.browser_fingerprint}")

        # Test with same fingerprint (should return existing device)
        device2 = device_identifier.identify_device_by_browser_fingerprint(
            "192.168.1.100",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "example.com"
        )
        print(f"Device 2 (same fingerprint): {device2.id}, should be same as device1: {device1.id == device2.id}")

        # Test with different fingerprint
        device3 = device_identifier.identify_device_by_browser_fingerprint(
            "192.168.1.101",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "google.com"
        )
        print(f"Device 3 (different): {device3.id}, fingerprint: {device3.browser_fingerprint}")

        print("Hybrid identification test passed!")

    except Exception as e:
        print(f"Error in hybrid identification test: {e}")
        import traceback
        traceback.print_exc()