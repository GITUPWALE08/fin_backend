import os
import time

from cs50 import SQL
from flask import Flask, session, jsonify, request
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix 
from flask_cors import CORS
from config import Config
from helpers import login_required, lookup, usd

# Configure application
app = Flask(__name__)

# --- 1. PROXY FIX (CRITICAL) ---
# This allows Flask to trust that Vercel is handling HTTPS
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- 2. SESSION CONFIGURATION ---
# Use a static key so sessions survive restarts
app.config["SECRET_KEY"] = "super_secret_static_key_12345"
app.config["SESSION_PERMANENT"] = True

# IMPORTANT: Remove 'SESSION_TYPE' if you deleted 'Session(app)'
# If you are using default Flask sessions, you do NOT need this line.

# --- 3. COOKIE SETTINGS (The "Safe Mode") ---
# We use "None" because it works for BOTH Direct and Proxy connections.
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

# CRITICAL: Do NOT set SESSION_COOKIE_DOMAIN. 
# By leaving it empty, the cookie automatically belongs to "finance-three-sepia.vercel.app"
# app.config["SESSION_COOKIE_DOMAIN"] = None  <-- Default is None, so just don't set it.

# --- 4. CORS ---
# Even with Proxy, keep this for safety.
CORS(app, 
     supports_credentials=True, 
     origins=["https://finance-three-sepia.vercel.app", "http://localhost:5173"]
)

# FRONTEND_URL = "https://finance-three-sepia.vercel.app"

# # This tells Flask: "I am behind a proxy (Vercel). Trust that the connection is Secure (HTTPS)."
# app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# # --- CONFIGURATION ---
# app.config["SESSION_PERMANENT"] = True
# app.config["SECRET_KEY"] = "server_secret_key"

# # Security settings for production

# app.config["SESSION_COOKIE_SECURE"] = True
# app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_HTTPONLY"] = True


# Session(app)


# --- DATABASE CONFIGURATION ---
# Check if DATABASE_URL exists (Production)
uri = os.environ.get("DATABASE_URL")

if uri:
    # Fix for Render's URL format (Postgres requires 'postgresql://', Render sometimes gives 'postgres://')
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    db = SQL(uri)
else:
    # Fallback for Local Development
    db = SQL("sqlite:///finance.db")

# CORS is technically not needed if using Proxy, but keeping it is safe.
#CORS(app, supports_credentials=True, origins=[FRONTEND_URL, "http://localhost:5173"])

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/portfolio")
@login_required
def index():
    """Show portfolio of stocks as JSON"""
    if session.get("user_id"):
        # Get stocks
        users_index = db.execute("SELECT * FROM portfolio WHERE user_id=? ORDER BY shares DESC;", session["user_id"])
        if not users_index:
            session.clear() # Clear the dead session
            return jsonify({"error": "Session expired (Server Restart). Please login again."}), 403
        
        # Get cash
        user_info = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
        cash = user_info[0]["cash"]
        
        portfolio_total = cash
        
        # Update prices
        for stock in users_index:
            look_up = lookup(stock["symbol"])
            if look_up:
                stock["price"] = look_up["price"]
                stock["name"] = look_up["name"]
                stock["total"] = look_up["price"] * stock["shares"]
                portfolio_total += stock["total"]
        
        # FIX: Return JSON instead of HTML
        return jsonify({
            "portfolio": users_index,
            "cash": cash,
            "total": portfolio_total
        })
    return jsonify({"error": "Not logged in"}), 403

@app.route("/buy", methods=["POST"])
@login_required
def buy():
    """Buy shares of stock"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    symbol = data.get("symbol", "").upper()
    password = data.get("password")
    
    # Validation
    look_up = lookup(symbol)
    if not symbol or not look_up:
        return jsonify({"error": "Invalid symbol"}), 400
    elif not password:
        return jsonify({"error": "Must enter password"}), 400
    
    try:
        shares = float(data.get("shares"))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid shares"}), 400

    if shares <= 0:
        return jsonify({"error": "Invalid shares"}), 400
    
    # Get user
    user_details = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    if not user_details:
        return jsonify({"error": "Not logged in"}), 403
    
    if not check_password_hash(user_details[0]["hash"], password):
        return jsonify({"error": "Incorrect password"}), 403
    
    amount = look_up["price"] * shares
    if user_details[0]["cash"] < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    try:
        # 1. Record purchase (REMOVED Python time, REMOVED 'time_stamp' typo)
        # Let Postgres handle the timestamp automatically
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, 'buy');", 
                   user_details[0]["id"], symbol, shares, look_up["price"])
        
        # 2. Update cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?;", amount, user_details[0]["id"])
        
        # 3. Update portfolio (Upsert)
        db.execute("""
            INSERT INTO portfolio (user_id, symbol, shares) 
            VALUES (?, ?, ?) 
            ON CONFLICT(user_id, symbol) 
            DO UPDATE SET shares = shares + excluded.shares;
        """, session["user_id"], symbol, shares)
        
    except ValueError:
        return jsonify({"error": "Transaction failed"}), 400

    return jsonify({"message": "Purchase completed"}), 200

@app.route("/sell", methods=["POST"])
@login_required
def sell():
    """Sell shares of stock"""
    data = request.get_json()
    if not data:
         return jsonify({"error": "Invalid JSON"}), 400

    symbol = data.get("symbol", "").upper()
    look_up = lookup(symbol)
    
    if not symbol or not look_up:
        return jsonify({"error": "Invalid Symbol"}), 400
    
    try:
        shares = float(data.get("shares"))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid shares"}), 400
        
    if shares <= 0:
        return jsonify({"error": "Invalid shares"}), 400
    
    # Check ownership
    user_stock = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
    
    if not user_stock:
        return jsonify({"error": "You do not own this stock"}), 400
    
    if user_stock[0]["shares"] < shares:
        return jsonify({"error": "Insufficient share balance"}), 400
    
    amount = look_up["price"] * shares

    try:
        # 1. Record sale (FIXED table name 'transactions', REMOVED python time)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, 'sell');", 
                   session["user_id"], symbol, shares, look_up["price"])
        
        # 2. Update cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?;", amount, session["user_id"])
        
        # 3. Update portfolio
        db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?", 
                   shares, session["user_id"], symbol)
                   
        # 4. Clean up empty stocks
        db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ? AND shares = 0", session["user_id"], symbol)
        
    except ValueError:
        return jsonify({"error": "Transaction failed"}), 400

    return jsonify({"message": "Sold successfully"}), 200


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # FIX: Changed 'time' to 'timestamp'
    user_data = db.execute("SELECT symbol, shares, price, type, timestamp as time FROM transactions WHERE user_id = ? ORDER BY timestamp DESC;", session["user_id"])
    return jsonify({"history": user_data})


@app.route("/login", methods=["POST"])
def login():
    """Log user in"""
    session.clear()
    
    if request.method == "POST":
        data = request.get_json()
        if not data or not data.get("username") or not data.get("password"):
            return jsonify({"error": "Missing credentials"}), 400

        rows = db.execute("SELECT * FROM users WHERE username = ?", data.get("username").lower())

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], data.get("password")):
            return jsonify({"error": "Invalid username and/or password"}), 400

        session["user_id"] = rows[0]["id"]
        return jsonify({
            "message": "Login successful", 
            "user_id": rows[0]["id"], 
            "user_name": rows[0]["username"]
        }), 200

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/current_user")
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"user": None}), 200

    users = db.execute("SELECT id, username FROM users WHERE id = ?", user_id)
    if not users:
        return jsonify({"user": None}), 200

    return jsonify({
        "user": {
            "id": users[0]["id"], 
            "username": users[0]["username"]
        }
    }), 200

@app.route("/quote", methods=["POST"])
def quote():
    # FIX: Use get_json()
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
        
    quote = lookup(data.get("symbol", "").upper())
    if not quote:
        return jsonify({"error": "Invalid symbol"}), 400
        
    return jsonify({"price": quote["price"], "name": quote["name"]})

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username").lower()
    password = data.get("password")
    confirm = data.get("confirmation") # Ensure your React form sends this key!

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
        
    hash_password = generate_password_hash(password)
    try:
        new_user_id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash_password)
        session["user_id"] = new_user_id
        return jsonify({"message": "Registered successfully"}), 201
    except ValueError:
        return jsonify({"error": "Username already exists"}), 400

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username").lower()
    last_password = data.get("last_password")
    recent_password = data.get("recent_password")
    confirm_recent = data.get("confirm_password")

    if not username or not last_password or not recent_password or not confirm_recent:
        return jsonify({"error": "Fill all fields"}), 400

    if confirm_recent != recent_password:
        return jsonify({"error": "Passwords do not match"}), 400
    
    user = db.execute("SELECT * FROM users WHERE username = ?", username)
    if not user or user[0]["id"] != session["user_id"]:
        return jsonify({"error": "Unauthorized"}), 400

    if not check_password_hash(user[0]["hash"], last_password):
        return jsonify({"error": "Incorrect password"}), 400
    
    new_hash = generate_password_hash(recent_password)
    db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user[0]["id"])
    
    return jsonify({"message": "Password changed successfully"}), 200

@app.route("/price")
def api_price():
    symbol = request.args.get("symbol").upper()

    # Example: lookup price from API
    look_up = lookup(symbol) 

    if not look_up:
        return jsonify({"error": "Invalid symbol"}), 400
    
    return jsonify({"price": look_up["price"], "name": look_up["name"]})

@app.route("/init_db")
def init_db():
    try:
        # 1. USERS TABLE
        # Uses 'SERIAL' for auto-incrementing IDs in Postgres
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL,
                cash NUMERIC NOT NULL DEFAULT 10000.00 CHECK (cash >= 0)
            );
        """)

        # 2. TRANSACTIONS TABLE (Optimized: Combines history, buy, and sell)
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                symbol TEXT NOT NULL,
                shares NUMERIC NOT NULL CHECK (shares > 0),
                price NUMERIC NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('buy', 'sell')), 
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. PORTFOLIO TABLE (Tracks current holdings)
        db.execute("""
            CREATE TABLE IF NOT EXISTS portfolio (
                user_id INTEGER NOT NULL REFERENCES users(id),
                symbol TEXT NOT NULL,
                shares NUMERIC NOT NULL CHECK (shares >= 0),
                PRIMARY KEY (user_id, symbol)
            );
        """)

        # 4. INDEXES (For speed)
        # Note: We use 'CREATE INDEX IF NOT EXISTS' to avoid errors if run twice
        db.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_portfolio_user ON portfolio(user_id);")

        return "Database initialized successfully with Optimized Schema!", 200

    except Exception as e:
        return f"An error occurred: {e}", 500

if __name__ == "__main__":
    app.run(debug=True)