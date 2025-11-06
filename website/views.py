from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from .db_utils import fetch_secrets, insert_secret, delete_secret_by_id
from .crypto_utils import *
import base64
from functools import wraps
import bleach
from cerberus import Validator
import re

views = Blueprint("views", __name__)

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "error")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapped

# Add input validation schemas
secret_schema = {
    'label': {'type': 'string', 'minlength': 1, 'maxlength': 100, 'regex': '^[\w\s\-\.]+$'},
    'site_username': {'type': 'string', 'minlength': 1, 'maxlength': 128},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 128}
}

@views.route("/vault")
@jwt_required()  # Change from @login_required to @jwt_required()
def vault():
    try:
        # Get user_id from JWT
        user_id = int(get_jwt_identity())
        
        secrets = fetch_secrets(user_id)
        print(f"Found {len(secrets)} secrets for user {user_id}")
        
        # Sanitize data before sending to template
        for secret in secrets:
            secret['label'] = bleach.clean(secret['label'])
            secret['login_username'] = bleach.clean(secret['login_username'])
            
        return render_template("vault.html", secrets=secrets)
        
    except Exception as e:
        print(f"Error accessing vault: {str(e)}")
        flash("Error accessing vault.", "error")
        return redirect(url_for("auth.login"))

@views.route("/add", methods=["GET", "POST"])   
@jwt_required()  
def add_secret():  
    if request.method == "POST":  
        # Validate input
        validator = Validator(secret_schema)
        data = {
            'label': request.form.get('label', '').strip(),
            'site_username': request.form.get('site_username', '').strip(),
            'password': request.form.get('password', '')
        }
        
        if not validator.validate(data):
            flash(f"Invalid input: {validator.errors}", "error")
            return redirect(url_for("views.add_secret"))

        # Sanitize input
        label = bleach.clean(data['label'])
        login_username = bleach.clean(data['site_username'])
        password = data['password']

        key = base64.b64decode(session["ekey"])  

        iv, ciphertext = encrypt(password, key)  

        insert_secret(session["user_id"], label, login_username, iv, ciphertext)  

        flash("Password saved successfully!", "success")
        return redirect(url_for("views.vault"))  
    
    return render_template("add_secret.html")  

@views.route("/api_secrets")   
@jwt_required()  
def api_secrets():    
    secrets = fetch_secrets(session["user_id"])  

    rows = [{ "id": s["id"], 
             "label": s["label"], 
             "login_username": s["login_username"], 
             "ciphertext_b64": s["ciphertext"] } for s in secrets]  
    
    return jsonify(rows=rows)

@views.route("/reveal/<int:secret_id>")  
@jwt_required() 
def reveal_secret(secret_id):
    try:
        # Get secrets for current user
        user_id = int(get_jwt_identity())
        secrets = fetch_secrets(user_id)
        
        # Find the requested secret
        secret = next((s for s in secrets if s["id"] == secret_id), None)
        if not secret:
            return jsonify({"error": "Secret not found"}), 404
            
        # Get encryption key from session
        key = base64.b64decode(session["ekey"])
        
        # Decrypt the password
        password = decrypt(secret["iv"], secret["ciphertext"], key)
        
        return jsonify({
            "password": password,
            "label": secret["label"],
            "login_username": secret["login_username"]
        })
        
    except Exception as e:
        print(f"Error revealing secret: {str(e)}")
        return jsonify({"error": "Failed to decrypt password"}), 500


@views.route("/delete/<int:secret_id>", methods=["POST"])
@jwt_required()
def delete_secret(secret_id):  
    try:
        delete_secret_by_id(session["user_id"], secret_id)
        flash("Password deleted successfully!", "success")
    except Exception as e:
        print(f"Error deleting secret: {e}")
        flash("Error deleting password.", "error")
    
    return redirect(url_for("views.vault"))



