#!/usr/bin/env python3
import os
import sys
import logging
from app import create_app

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting WiFi IDS System...")
        app = create_app()
        
        logger.info("=" * 60)
        logger.info("WiFi IDS Dashboard: http://localhost:5000")
        logger.info("API Base: http://localhost:5000/api/v1")
        logger.info("=" * 60)
        
        app.run(
            debug=os.environ.get('FLASK_ENV') == 'development',
            host='0.0.0.0',
            port=5000,
            use_reloader=False
        )
    
    except KeyboardInterrupt:
        logger.info("Shutting down WiFi IDS System...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
