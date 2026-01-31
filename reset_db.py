import os
import shutil
from app import create_app, db

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        db_path = 'wifi_ids.db'
        
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"Deleted {db_path}")
        
        models_dir = 'models'
        if os.path.exists(models_dir):
            for file in os.listdir(models_dir):
                if file.endswith('.pkl'):
                    os.remove(os.path.join(models_dir, file))
                    print(f"Deleted {file}")
        
        db.create_all()
        print("Database recreated successfully")
        print("\nAll old alerts and devices cleared!")
        print("Anomaly model reset - will auto-train when capture starts")
