import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect  # Changed from SeaSurf
from .views import views
from .auth import auth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def build_app():
    app = Flask(__name__)
    
    # CSRF Protection
    csrf = CSRFProtect(app)  # Changed from SeaSurf
    
    # Use secrets from environment variables
    app.secret_key = os.environ.get("SECRET_KEY")
    if not app.secret_key:
        raise ValueError("No SECRET_KEY set for Flask application")
    
    # Session Configuration
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour in seconds
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    
    # JWT Configuration
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
    if not app.config["JWT_SECRET_KEY"]:
        raise ValueError("No JWT_SECRET_KEY set for Flask application")
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_COOKIE_SECURE"] = True
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 86400

    # Configure Talisman
    csp = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'"
    }
    
    Talisman(app,
             force_https=False,  # Set to True in production
             strict_transport_security=True,
             session_cookie_secure=False,  # Set to True in production
             content_security_policy=csp)
    
    # Initialize JWT
    jwt = JWTManager(app)
    
    app.register_blueprint(views)
    app.register_blueprint(auth)
    
    return app


