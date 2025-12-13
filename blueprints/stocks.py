from flask import Blueprint, request, jsonify
from helpers import lookup
from helpers import login_required

stocks_bp = Blueprint("stocks", __name__, url_prefix="/api/stocks")


@stocks_bp.get("/api/price")
@login_required
def price():
    symbol = request.args.get("symbol", "").upper()
    quote = lookup(symbol)

    if not quote:
        return jsonify({"error": "Invalid symbol"}), 400

    return jsonify({"price": quote["price"], "name": quote["name"]})
