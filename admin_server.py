from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
import os, json, hashlib, binascii, time
from datetime import datetime
from functools import wraps

APP_SECRET = os.environ.get("APP_SECRET", "change_me_now")  # change before production
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "adminpass")     # change immediately in production

USERS_FILE = os.environ.get("USERS_FILE", "users.json")

app = Flask(__name__)
app.secret_key = APP_SECRET

# ----------------- password helpers (PBKDF2) -----------------
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return binascii.hexlify(salt).decode('ascii'), binascii.hexlify(dk).decode('ascii')

def verify_password(password, salt_hex, hash_hex):
    salt = binascii.unhexlify(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return binascii.hexlify(dk).decode('ascii') == hash_hex

# ----------------- users storage helpers -----------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def migrate_legacy(users):
    """Ensure every user has required fields"""
    changed = False
    for u, e in list(users.items()):
        if 'salt' not in e or 'hash' not in e:
            # if plain password stored (legacy), convert it
            if 'password' in e:
                salt, h = hash_password(e['password'])
                e['salt'] = salt; e['hash'] = h
                e.pop('password', None)
                changed = True
        e.setdefault('devices', {})
        e.setdefault('max_devices', 1)
        e.setdefault('expires', None)
        users[u] = e
    if changed:
        save_users(users)
    return users

# ----------------- admin auth decorator -----------------
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("admin_logged") != True:
            return redirect(url_for("admin_login", next=request.url))
        return f(*args, **kwargs)
    return decorated

# ----------------- web admin routes -----------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        if user == ADMIN_USER and pw == ADMIN_PASS:
            session["admin_logged"] = True
            flash("Login sukses", "success")
            return redirect(url_for("admin_users"))
        flash("Login gagal", "danger")
    return render_template("base.html", title="Admin Login", body="""
    <div class="container mt-5" style="max-width:420px">
      <h4>Admin Login</h4>
      <form method="post">
        <div class="mb-3">
          <input class="form-control" name="username" placeholder="username" />
        </div>
        <div class="mb-3">
          <input class="form-control" name="password" placeholder="password" type="password" />
        </div>
        <button class="btn btn-primary">Login</button>
      </form>
    </div>
    """)

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged", None)
    return redirect(url_for("admin_login"))

@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    users = migrate_legacy(users)
    return render_template("users.html", users=users)

@app.route("/admin/create", methods=["GET", "POST"])
@admin_required
def admin_create():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        max_devices = int(request.form.get("max_devices") or 1)
        expires = request.form.get("expires") or None
        if expires:
            try:
                datetime.strptime(expires, "%Y-%m-%d")
            except Exception:
                flash("Format expires harus YYYY-MM-DD", "warning")
                return redirect(url_for("admin_create"))
        users = load_users()
        if username in users:
            flash("User sudah ada", "warning")
            return redirect(url_for("admin_users"))
        salt, h = hash_password(password)
        users[username] = {"salt": salt, "hash": h, "devices": {}, "max_devices": max_devices, "expires": expires}
        save_users(users)
        flash(f"User {username} dibuat", "success")
        return redirect(url_for("admin_users"))
    return render_template("base.html", title="Create User", body="""
    <div class="container mt-4" style="max-width:720px">
      <h4>Create User</h4>
      <form method="post">
        <div class="mb-3"><input class="form-control" name="username" placeholder="username" required /></div>
        <div class="mb-3"><input class="form-control" name="password" placeholder="password" required /></div>
        <div class="mb-3"><input class="form-control" name="max_devices" placeholder="max devices (1)" /></div>
        <div class="mb-3"><input class="form-control" name="expires" placeholder="expires YYYY-MM-DD (optional)" /></div>
        <button class="btn btn-success">Create</button>
        <a class="btn btn-secondary" href="/admin/users">Cancel</a>
      </form>
    </div>
    """)

@app.route("/admin/edit/<username>", methods=["GET", "POST"])
@admin_required
def admin_edit(username):
    users = load_users()
    if username not in users:
        flash("User tidak ditemukan", "warning")
        return redirect(url_for("admin_users"))
    if request.method == "POST":
        password = request.form.get("password")
        max_devices = int(request.form.get("max_devices") or users[username].get("max_devices",1))
        expires = request.form.get("expires") or None
        if password:
            salt, h = hash_password(password)
            users[username]["salt"] = salt
            users[username]["hash"] = h
        users[username]["max_devices"] = max_devices
        users[username]["expires"] = expires
        save_users(users)
        flash("User diperbarui", "success")
        return redirect(url_for("admin_users"))

    user = users[username]
    return render_template("edit_user.html", username=username, user=user)

@app.route("/admin/unbind/<username>", methods=["POST"])
@admin_required
def admin_unbind(username):
    users = load_users()
    if username not in users:
        return jsonify({"status":"error","message":"user not found"}), 404
    users[username]["devices"] = {}
    save_users(users)
    flash(f"Semua device untuk {username} di-unbind", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/delete/<username>", methods=["POST"])
@admin_required
def admin_delete(username):
    users = load_users()
    if username in users:
        users.pop(username)
        save_users(users)
        flash(f"User {username} dihapus", "success")
    else:
        flash("User tidak ditemukan", "warning")
    return redirect(url_for("admin_users"))

# ----------------- keep existing API endpoints for license checks -----------------
@app.route("/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    device = data.get("device", "")
    if not username or not password:
        return jsonify({"status":"error","message":"username/password required"}), 400

    users = load_users()
    users = migrate_legacy(users)
    user = users.get(username)
    if not user:
        return jsonify({"status":"error","message":"user not found"}), 404

    if not verify_password(password, user.get("salt"), user.get("hash")):
        return jsonify({"status":"error","message":"invalid credentials"}), 401

    # expiry check
    exp = user.get("expires")
    if exp:
        try:
            if isinstance(exp, (int, float)):
                if time.time() > float(exp):
                    return jsonify({"status":"error","message":"license expired"}), 403
            else:
                dt = datetime.strptime(exp, "%Y-%m-%d")
                if datetime.now() > dt:
                    return jsonify({"status":"error","message":"license expired"}), 403
        except Exception:
            pass

    # device handling
    import hashlib as _h
    device_id = _h.sha256(device.encode('utf-8')).hexdigest()
    devices = user.get("devices") or {}
    max_devices = int(user.get("max_devices", 1))
    if device_id in devices:
        return jsonify({"status":"ok","message":"login successful","username":username,"devices":list(devices.keys())})
    else:
        if len(devices) < max_devices:
            devices[device_id] = {"activated": datetime.utcnow().isoformat()}
            user["devices"] = devices
            users[username] = user
            save_users(users)
            return jsonify({"status":"ok","message":"device registered and login successful","username":username,"devices":list(devices.keys())})
        else:
            return jsonify({"status":"error","message":"device limit reached","max_devices":max_devices,"devices":list(devices.keys())}), 403

# health
@app.route("/")
def index():
    return "Indotex License Server with Admin Panel ✅"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
