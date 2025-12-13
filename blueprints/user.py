from flask import Blueprint, jsonify, session
from database import db
from helpers import login_required

user_bp = Blueprint("user", __name__)


@user_bp.get("/portfolio")
@login_required
def portfolio():
    rows = db.execute("SELECT * FROM current_stock WHERE user_id = ?", session["user_id"])
    return jsonify({"portfolio": rows})
