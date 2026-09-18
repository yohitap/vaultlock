import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from crypto_utils import derive_key, encrypt_text, decrypt_text, verify_password_strength
from db import init_db, get_db, close_db
from services import (
    create_entry, list_entries, get_entry, update_entry, delete_entry,
    calculate_health, record_audit, get_audit_log
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("VAULTLOCK_SECRET", "change-this-development-secret")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

init_db()
app.teardown_appcontext(close_db)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        master = request.form.get("master_password", "")

        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
            return render_template("register.html")

        ok, message = verify_password_strength(master)
        if not ok:
            flash(message, "error")
            return render_template("register.html")

        db = get_db()
        try:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("That username is already registered.", "error")
                return render_template("register.html")

            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(master), datetime.utcnow().isoformat())
            )
            db.commit()
            flash("Vault created. You can now sign in.", "success")
            return redirect(url_for("login"))
        finally:
            pass

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        master = request.form.get("master_password", "")

        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], master):
            flash("Invalid username or master password.", "error")
            return render_template("login.html")

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        from services import unlock_user_key
        unlock_user_key(user["id"], master)

        record_audit(user["id"], "LOGIN", "Successful login")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        record_audit(session["user_id"], "LOGOUT", "User logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    entries = list_entries(session["user_id"])
    health = calculate_health(entries)
    return render_template("dashboard.html", entries=entries, health=health)


@app.route("/entry/new", methods=["GET", "POST"])
@login_required
def new_entry():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        website = request.form.get("website", "").strip()
        category = request.form.get("category", "Other").strip()
        notes = request.form.get("notes", "").strip()

        if not title or not password:
            flash("Title and password are required.", "error")
            return render_template("entry_form.html", entry=None)

        create_entry(
            session["user_id"], title, username, password, website, category, notes
        )
        flash("Credential saved securely.", "success")
        return redirect(url_for("dashboard"))

    return render_template("entry_form.html", entry=None)


@app.route("/entry/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    entry = get_entry(session["user_id"], entry_id)
    if not entry:
        flash("Credential not found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        update_entry(
            session["user_id"],
            entry_id,
            request.form.get("title", "").strip(),
            request.form.get("username", "").strip(),
            request.form.get("password", ""),
            request.form.get("website", "").strip(),
            request.form.get("category", "Other").strip(),
            request.form.get("notes", "").strip(),
        )
        flash("Credential updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("entry_form.html", entry=entry)


@app.post("/entry/<int:entry_id>/delete")
@login_required
def remove_entry(entry_id):
    delete_entry(session["user_id"], entry_id)
    flash("Credential deleted.", "success")
    return redirect(url_for("dashboard"))


@app.get("/api/entry/<int:entry_id>")
@login_required
def api_entry(entry_id):
    entry = get_entry(session["user_id"], entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@app.get("/security")
@login_required
def security():
    entries = list_entries(session["user_id"])
    health = calculate_health(entries)
    audit = get_audit_log(session["user_id"])
    return render_template("security.html", health=health, audit=audit)


@app.post("/api/generate-password")
@login_required
def generate_password():
    from services import generate_secure_password
    length = min(max(int(request.json.get("length", 20)), 12), 64)
    return jsonify({"password": generate_secure_password(length)})


if __name__ == "__main__":
    app.run(debug=True)
