from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

# === Simulasi Database ===
USERS_FILE = "users.json"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "12345")


def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump([], f)
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=4)


# === ROUTES ===

@app.route("/")
def home():
    return "Indotex License Server with Admin Panel ✅"


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# --- Admin Login ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# --- Admin Dashboard ---
@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    users = load_users()
    return render_template("dashboard.html", users=users)


# --- API for managing users ---
@app.route("/api/users", methods=["GET", "POST"])
def api_users():
    if request.method == "GET":
        return jsonify(load_users())

    elif request.method == "POST":
        data = request.get_json()
        users = load_users()
        users.append(data)
        save_users(users)
        return jsonify({"status": "user added", "user": data})


@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

