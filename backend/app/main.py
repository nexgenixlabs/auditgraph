import os
# backend/app/main.py
from pathlib import Path
from dotenv import load_dotenv

# -------------------------------------------------------------------
# Load environment variables BEFORE importing modules that connect to DB
# -------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parents[1]  # .../backend
load_dotenv(BACKEND_DIR / ".env.local")            # local dev (real creds) - ignored by git
load_dotenv(BACKEND_DIR / ".env")                  # optional fallback
load_dotenv(BACKEND_DIR / ".env.example")          # safe fallback (placeholders)

from flask import Flask
from flask_cors import CORS
from app.api.routes import api_bp
from app.scheduler import start_scheduler, stop_scheduler
import atexit

def create_app() -> Flask:
    app = Flask(__name__)
    
    # Keep React dashboard working (allow localhost + your LAN IP for dev)
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                    "http://192.168.1.200:3000",
                ]
            }
        },
    )
    
    # Register API routes
    app.register_blueprint(api_bp, url_prefix="/api")
    
    # Start the scheduler when app starts
    start_scheduler()
    
    # Stop the scheduler when app shuts down
    atexit.register(stop_scheduler)
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=os.getenv("FLASK_DEBUG", "False").lower() == "true")