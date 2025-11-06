from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .db_utils import *
from .crypto_utils import *
import base64
import hmac
from datetime import timedelta
import re

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

auth = Blueprint("auth", __name__)

def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain special character"
    return True, ""

@auth.route("/", methods=["GET"])
def home():
    return redirect(url_for("auth.login"))

@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username")
            password = request.form.get("password")
            
            # Fetch user and validate
            user = fetch_user(username)
            if not user:
                flash("Invalid credentials.", "error")
                return redirect(url_for("auth.login"))
            
            # Verify password
            key, _ = derive_key(password, user["salt"])
            computed_hash = master_key_hash(key)
            
            if not hmac.compare_digest(computed_hash, user["master_key_hash"]):
                flash("Invalid credentials.", "error")
                return redirect(url_for("auth.login"))
            
            # Create access token with longer expiration
            access_token = create_access_token(
                identity=str(user["id"]),
                expires_delta=timedelta(hours=1)  # Match JWT_ACCESS_TOKEN_EXPIRES
            )
            
            # Create response with token
            response = make_response(redirect(url_for("views.vault")))
            set_access_cookies(response, access_token)
            
            # Set session data
            session["user_id"] = user["id"]
            session["ekey"] = base64.b64encode(key).decode()
            session.permanent = True
            
            flash("Login successful.", "success")
            return response
            
        except Exception as e:
            print(f"Error during login: {e}")
            flash("An error occurred during login.", "error")
            return redirect(url_for("auth.login"))
    
    return render_template("index.html")

@auth.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))

@auth.route("/create_account", methods=["GET", "POST"])
def create_account():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        
        # Validate username
        if not re.match(r'^[a-zA-Z0-9_]{3,64}$', username):
            flash("Invalid username format", "error")
            return redirect(url_for("auth.create_account"))
            
        # Validate password
        valid_pass, pass_error = validate_password(password)
        if not valid_pass:
            flash(pass_error, "error")
            return redirect(url_for("auth.create_account"))
        
        try:
            # Generate new salt and derive key
            salt = os.urandom(32)
            key, _ = derive_key(password, salt)
            
            # Convert to hex strings for storage
            salt_hex = salt.hex()
            mk_hash_hex = master_key_hash(key)
            
            print(f"Creating account with:")
            print(f"Salt (hex): {salt_hex}")
            print(f"Key (hex): {key.hex()}")
            print(f"Hash: {mk_hash_hex}")
            
            if not insert_user(username, salt_hex, mk_hash_hex):
                flash("Username already taken.", "error")
                return redirect(url_for("auth.create_account"))
                
            flash("Account created — log in.", "success")
            return redirect(url_for("auth.login"))
            
        except Exception as e:
            print(f"Error creating account: {e}")
            flash("Error creating account.", "error")
            return redirect(url_for("auth.create_account"))
    

    return render_template("create_account.html")




