#!/usr/bin/env python3
from app import create_app

if __name__ == '__main__':
    try:
        app = create_app()
        print("App initialized successfully")
        print("Database tables created")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()