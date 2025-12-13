from flask import Blueprint, jsonify, session
from database import db
from helpers import login_required

history_bp = Blueprint("history", __name__)


@history_bp.get("/")
@login_required
def get_history():
    rows = db.execute("SELECT * FROM history WHERE user_id = ? ORDER BY time DESC",
                      session["user_id"])
    return jsonify({"history": rows})
