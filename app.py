import os
import sqlite3
import hashlib
import time
import subprocess

from flask import (
    Flask, request, redirect, render_template,
    make_response, g, jsonify, url_for
)

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

DATABASE = app.config["DATABASE"]

LAST_QUERY = ""  # For /debug/sql


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize DB and seed data if not exists."""
    if os.path.exists(DATABASE):
        return
    db = sqlite3.connect(DATABASE)
    cur = db.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        is_admin INTEGER DEFAULT 0
    )
    """)

    # Products
    cur.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price REAL
    )
    """)

    # Reviews
    cur.execute("""
    CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        author TEXT,
        content TEXT
    )
    """)

    # Invoices
    cur.execute("""
    CREATE TABLE invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        details TEXT,
        flag TEXT
    )
    """)

    # Seed users (admin + normal users)
    cur.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ("admin", "admin123", "admin@vulnmart.local", 1)
    )
    cur.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ("alice", "password", "alice@vulnmart.local", 0)
    )
    cur.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ("bob", "123456", "bob@vulnmart.local", 0)
    )

    # Seed products (including one with flag in name for SQLi / UNION fun)
    cur.execute(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        ("VulnPhone X", "A very insecure smartphone.", 499.99)
    )
    cur.execute(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        ("FLAG{product_sqli_loot}", "Nothing to see here.", 0.00)
    )
    cur.execute(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        ("Budget Laptop", "Cheap and cheerful laptop.", 299.99)
    )

    # Sample reviews
    cur.execute(
        "INSERT INTO reviews (product_id, author, content) VALUES (?, ?, ?)",
        (1, "alice", "Works fine, I guess.")
    )

    # Seed invoices (IDOR flag)
    cur.execute(
        "INSERT INTO invoices (user_id, details, flag) VALUES (?, ?, ?)",
        (1, "Invoice #1 for alice\nItem: VulnPhone X\nAmount: 499.99",
         "FLAG{idor_leaky_invoices}")
    )
    cur.execute(
        "INSERT INTO invoices (user_id, details, flag) VALUES (?, ?, ?)",
        (2, "Invoice #2 for bob\nItem: Budget Laptop\nAmount: 299.99",
         "")
    )

    db.commit()
    db.close()


@app.before_first_request
def setup():
    # Ensure folders and db exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("flags", exist_ok=True)

    # Flags in files
    if not os.path.exists("flags/command.txt"):
        with open("flags/command.txt", "w") as f:
            f.write("FLAG{command_injection_shell}\n")
    if not os.path.exists("flags/logs_flag.txt"):
        with open("flags/logs_flag.txt", "w") as f:
            f.write("FLAG{directory_traversal_logs}\n")
    if not os.path.exists("logs/app.log"):
        with open("logs/app.log", "w") as f:
            f.write("VulnMart log file\n")

    init_db()


@app.after_request
def add_bad_headers(resp):
    # Misconfigured headers & header flag
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    resp.headers["Server"] = "FlaskDev/0.1 VulnMart"
    resp.headers["X-VulnMart-Flag"] = "FLAG{bad_security_headers}"
    return resp


def get_session_user():
    """Very naive session handling using a file."""
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None

    if not os.path.exists("sessions.txt"):
        return None

    with open("sessions.txt", "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            sid, uid, is_admin = parts[0], parts[1], parts[2]
            if sid == session_id:
                try:
                    return {"id": int(uid), "is_admin": int(is_admin)}
                except ValueError:
                    return None
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    global LAST_QUERY
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")

        # VULN: SQL Injection via string concatenation
        query = "SELECT id, username, is_admin FROM users WHERE username = '%s' AND password = '%s'" % (
            user, pw
        )
        LAST_QUERY = query
        db = get_db()
        cur = db.cursor()
        cur.execute(query)
        row = cur.fetchone()

        if row:
            user_id, username, is_admin = row

            # VULN: weak session token
            token_seed = "%s-%s" % (username, time.time())
            session_id = hashlib.md5(token_seed.encode()).hexdigest()

            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("session_id", session_id)  # no HttpOnly, no Secure

            # VULN: sessions.txt file with flag
            with open("sessions.txt", "a") as f:
                f.write("{},{},{}\n".format(session_id, user_id, is_admin))
                f.write("FLAG{weak_sessionid_roulette}\n")

            if is_admin:
                # Flag for admin login via SQLi
                resp.set_cookie("flag_login", "FLAG{login_sqli_pwned}")
            return resp

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")

        # VULN: store password in plaintext
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)",
                (username, password, email)
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already exists")
    return render_template("register.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    user = get_session_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, details FROM invoices WHERE user_id = ?", (user["id"],))
    invoices = cur.fetchall()

    discount_msg = ""
    if request.method == "POST":
        coupon = request.form.get("coupon", "")
        # Business logic flaw
        if coupon == "FREE100":
            discount_msg = "Coupon applied: 100% off EVERYTHING! FLAG{logic_flaw_free_money}"
        else:
            discount_msg = "Invalid coupon."

    return render_template("dashboard.html", invoices=invoices, discount_msg=discount_msg)


@app.route("/products")
def products():
    global LAST_QUERY
    search = request.args.get("search", "")
    db = get_db()
    cur = db.cursor()

    # VULN: SQL Injection + reflected XSS via search
    query = "SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'" % search
    LAST_QUERY = query
    cur.execute(query)
    rows = cur.fetchall()

    return render_template("products.html", products=rows, search=search)


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product_detail(product_id):
    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")

        # VULN: stored XSS (no sanitization)
        cur.execute(
            "INSERT INTO reviews (product_id, author, content) VALUES (?, ?, ?)",
            (product_id, author, content)
        )
        db.commit()

    cur.execute("SELECT id, name, description, price FROM products WHERE id = ?", (product_id,))
    product = cur.fetchone()

    cur.execute("SELECT author, content FROM reviews WHERE product_id = ?", (product_id,))
    reviews = cur.fetchall()

    return render_template("product.html", product=product, reviews=reviews)


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    user = get_session_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT user_id, details, flag FROM invoices WHERE id = ?", (invoice_id,))
    row = cur.fetchone()
    if not row:
        return "Not found", 404

    user_id, details, flag = row
    # VULN: no ownership check
    html = "<h1>Invoice #%d</h1><pre>%s</pre>" % (invoice_id, details)
    if flag:
        html += "<p>Note: %s</p>" % flag
    return html


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = get_session_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        email = request.form.get("email", "")
        # simple update
        cur.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
        db.commit()

    cur.execute("SELECT username, email FROM users WHERE id = ?", (user["id"],))
    row = cur.fetchone()

    return render_template("profile.html", user=row)


@app.route("/upload/avatar", methods=["POST"])
def upload_avatar():
    user = get_session_user()
    if not user:
        return redirect(url_for("login"))

    file = request.files.get("avatar")
    if not file:
        return "No file provided", 400

    # VULN: no validation
    filename = file.filename
    upload_path = os.path.join("uploads", filename)
    file.save(upload_path)

    return "Uploaded! Access it at /uploads/%s. Maybe hide FLAG{webshell_avatar_upload} in your webshell." % filename


@app.route("/contact", methods=["GET", "POST"])
def contact():
    message = ""
    echo = None
    if request.method == "POST":
        echo = request.form.get("message", "")
        message = "Thanks for contacting us!"
        # we could log or store, but here we just echo

    return render_template("contact.html", message=message, echo=echo)


@app.route("/admin")
def admin_panel():
    user = get_session_user()
    if not user:
        return redirect(url_for("login"))
    # VULN: does NOT verify is_admin
    return render_template("admin.html", flag="FLAG{admin_panel_no_acl}")


@app.route("/admin/users")
def admin_users():
    global LAST_QUERY
    q = request.args.get("search", "")
    db = get_db()
    cur = db.cursor()

    # VULN: SQL Injection
    query = "SELECT id, username, email FROM users WHERE username LIKE '%%%s%%'" % q
    LAST_QUERY = query
    cur.execute(query)
    users = cur.fetchall()
    return render_template("admin_users.html", users=users, q=q)


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: command injection
    cmd = "ping -c 1 %s" % host
    result = subprocess.getoutput(cmd)
    return "<h1>Ping result</h1><pre>%s</pre>" % result


@app.route("/logs")
def logs():
    filename = request.args.get("file", "app.log")
    path = os.path.join("logs", filename)
    try:
        with open(path, "r") as f:
            content = f.read()
    except OSError:
        content = "File not found"
    return "<h1>Log viewer</h1><pre>%s</pre>" % content


@app.route("/debug/env")
def debug_env():
    env_dump = "\n".join(["%s=%s" % (k, v) for k, v in os.environ.items()])
    return "<pre>%s\nFLAG{debug_env_leak}</pre>" % env_dump


@app.route("/debug/sql")
def debug_sql():
    return "<h1>Last SQL query</h1><pre>%s</pre>" % LAST_QUERY


@app.route("/api/user/<user_id>")
def api_user(user_id):
    db = get_db()
    cur = db.cursor()
    try:
        # VULN: assuming integer; invalid input triggers error
        cur.execute("SELECT id, username, email FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        if not row:
            raise Exception("User not found, FLAG{verbose_error_stacktrace}")
        return jsonify({"id": row[0], "username": row[1], "email": row[2]})
    except Exception as e:
        # VULN: returns full exception
        return jsonify({"error": str(e)}), 500


@app.route("/api/search")
def api_search():
    term = request.args.get("term", "")
    key = request.args.get("key", "")
    # Basic JSON response; can be abused for reflected XSS via error fields

    if not key:
        return jsonify({"error": "Missing key for term: %s" % term}), 400

    return jsonify({"result": "No products found for '%s' using key '%s'" % (term, key)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)