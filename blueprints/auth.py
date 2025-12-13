from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/api/auth/login")
def login():
    data = request.get_json()
    user = data.get("username")
    password = data.get("password")

    if not user or not password:
        return jsonify({"error": "Missing fields"}), 400

    rows = db.execute("SELECT * FROM users WHERE username = ?", user)
    if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = rows[0]["id"]
    return jsonify({"message": "Login successful", "user_id": rows[0]["id"]}), 200


@auth_bp.post("/api/auth/register")
def register():
    data = request.get_json()
    u = data.get("username")
    p = data.get("password")
    c = data.get("confirm")

    if not u or not p:
        return jsonify({"error": "Missing credentials"}), 400

    if p != c:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   u, generate_password_hash(p))
    except Exception:
        return jsonify({"error": "Username already exists"}), 400

    return jsonify({"message": "Registered successfully"}), 201


@auth_bp.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})
