from flask import Blueprint, request, jsonify, session
from database import db
from helpers import login_required
from helpers import lookup
import time
from werkzeug.security import check_password_hash

trading_bp = Blueprint("trading", __name__)


@trading_bp.post("/buy")
@login_required
def buy():
    data = request.get_json()
    symbol = data.get("symbol", "").upper()
    shares = float(data.get("shares", 0))
    password = data.get("password")

    # Validate
    quote = lookup(symbol)
    if not quote:
        return jsonify({"error": "Invalid symbol"}), 400

    if shares <= 0:
        return jsonify({"error": "Invalid shares"}), 400

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

    if not check_password_hash(user["hash"], password):
        return jsonify({"error": "Incorrect password"}), 403

    cost = shares * quote["price"]

    if user["cash"] < cost:
        return jsonify({"error": "Insufficient balance"}), 400

    timestamp = time.strftime("%d/%m/%y %H:%M:%S")

    # Execute
    db.execute("INSERT INTO purchases (user_id, stock, shares, price, buy_time) VALUES (?, ?, ?, ?, ?)",
               user["id"], symbol, shares, quote["price"], timestamp)

    db.execute("INSERT INTO history (user_id, stock, shares, price, buy, time) VALUES (?, ?, ?, ?, ?, ?)",
               user["id"], symbol, shares, quote["price"], 1, timestamp)

    db.execute("UPDATE users SET cash = ? WHERE id = ?",
               user["cash"] - cost, user["id"])

    db.execute("""
        INSERT INTO current_stock (user_id, stock, shares)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, stock)
        DO UPDATE SET shares = shares + excluded.shares
    """, user["id"], symbol, shares)

    return jsonify({"message": "Purchase completed"}), 200
