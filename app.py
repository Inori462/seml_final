from flask import Flask, abort, current_app, flash, g, has_app_context, render_template, request, session, redirect, url_for
import re
import os
import secrets
import hmac
import threading
from urllib.parse import urlencode
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from decimal import Decimal, InvalidOperation
import click
from dotenv import load_dotenv

load_dotenv()

try:
    import mysql.connector
    from mysql.connector import IntegrityError
    from mysql.connector.pooling import MySQLConnectionPool
except ImportError:
    mysql = None
    MySQLConnectionPool = None

    class IntegrityError(Exception):
        pass

from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
configured_secret = (os.getenv("APP_SECRET_KEY") or os.getenv("SECRET_KEY") or "").strip()
if APP_ENV == "production" and (
    len(configured_secret) < 32
    or configured_secret == "change-me-to-a-long-random-secret"
):
    raise RuntimeError("APP_SECRET_KEY must contain at least 32 characters in production.")
app.config["SECRET_KEY"] = configured_secret or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
secure_cookie_default = "true" if APP_ENV == "production" else "false"
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE",
    secure_cookie_default
).strip().lower() in {"1", "true", "yes", "on"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")))


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="The request could not be verified. Refresh the page and try again.")
    return None


@app.errorhandler(requests.RequestException)
def handle_external_request_error(error):
    current_app.logger.warning("External HTTP request failed: %s", error)
    if request.path in {"/buyer/ai-support/chat", "/seller/ai-assistant/chat"}:
        return {"error": "The local AI service is unavailable."}, 503
    return render_template(
        "auth/login.html",
        error="Google sign-in could not be completed. Please try again.",
        email=""
    ), 502


def _internal_error_response(error, operation):
    current_app.logger.error(
        "%s",
        operation,
        exc_info=(type(error), error, error.__traceback__)
    )
    return "The request could not be completed. Please try again.", 500


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:5000/google/callback").strip()
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


# =========================================================
# MYSQL CONNECTION
# =========================================================

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB", "women_empowerment")


MYSQL_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
_db_pool = None
_db_pool_lock = threading.Lock()


def _get_db_pool():
    global _db_pool
    if mysql is None or MySQLConnectionPool is None:
        raise RuntimeError("mysql-connector-python is required to access the database.")
    if _db_pool is None:
        with _db_pool_lock:
            if _db_pool is None:
                _db_pool = MySQLConnectionPool(
                    pool_name="sherise_pool",
                    pool_size=MYSQL_POOL_SIZE,
                    pool_reset_session=True,
                    host=MYSQL_HOST,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=MYSQL_DB
                )
    return _db_pool


def _get_db_connection():
    if not has_app_context():
        raise RuntimeError("Database access requires an active Flask application context.")
    connection = g.get("db_connection")
    if connection is None:
        connection = _get_db_pool().get_connection()
        g.db_connection = connection
    return connection


class DatabaseProxy:
    def __getattr__(self, name):
        return getattr(_get_db_connection(), name)


db = DatabaseProxy()


@app.cli.command("create-admin")
@click.option("--email", prompt=True, help="Email address for the administrator.")
@click.option("--full-name", prompt=True, help="Administrator's display name.")
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Use a unique password with at least 12 characters."
)
def create_admin(email, full_name, password):
    email = email.strip().lower()
    full_name = full_name.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise click.ClickException("Enter a valid email address.")
    if not full_name or len(full_name) > 150:
        raise click.ClickException("Enter a name of 1 to 150 characters.")
    if len(password) < 12:
        raise click.ClickException("Administrator passwords must be at least 12 characters.")

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, role FROM users WHERE email = %s", (email,))
        existing = cursor.fetchone()
        password_hash = generate_password_hash(password)
        if existing:
            if existing["role"] != "admin":
                raise click.ClickException("That email belongs to a non-administrator account.")
            cursor.execute("""
                UPDATE users
                SET full_name = %s, password = %s
                WHERE id = %s AND role = 'admin'
            """, (full_name, password_hash, existing["id"]))
        else:
            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, 'admin')
            """, (full_name, email, "0000000000", password_hash))
        db.commit()
        click.echo("Administrator credentials have been provisioned.")
    except click.ClickException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        current_app.logger.exception("Administrator provisioning failed.")
        raise click.ClickException("Administrator provisioning failed; check the database connection and schema.") from e
    finally:
        if cursor:
            cursor.close()


@app.teardown_appcontext
def release_db_connection(error=None):
    connection = g.pop("db_connection", None)
    if connection is None:
        return
    try:
        connection.rollback()
    except Exception:
        current_app.logger.exception("Failed to roll back the request database connection.")
    finally:
        connection.close()


# =========================================================
# DATABASE HELPER
# =========================================================

def ensure_db_connection():
    connection = _get_db_connection()
    connection.ping(reconnect=True, attempts=3, delay=1)


def ensure_auth_security_tables():
    ensure_db_connection()


def login_locked(email):
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT failed_attempts, first_failed_at, locked_until
            FROM login_attempts
            WHERE email = %s
        """, (email,))
        record = cursor.fetchone()
        if not record:
            return False

        if record["locked_until"] and record["locked_until"] > datetime.now():
            return True

        if record["first_failed_at"] and datetime.now() - record["first_failed_at"] > timedelta(minutes=15):
            cursor.execute("DELETE FROM login_attempts WHERE email = %s", (email,))
            db.commit()
            return False

        return False
    finally:
        if cursor:
            cursor.close()


def register_failed_login(email):
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT failed_attempts, first_failed_at, locked_until
            FROM login_attempts
            WHERE email = %s
        """, (email,))
        record = cursor.fetchone()
        now = datetime.now()

        if not record:
            cursor.execute("""
                INSERT INTO login_attempts (email, failed_attempts, first_failed_at, last_failed_at)
                VALUES (%s, 1, %s, %s)
            """, (email, now, now))
            db.commit()
            return False

        if record["locked_until"] and record["locked_until"] > now:
            return True

        if record["first_failed_at"] and now - record["first_failed_at"] > timedelta(minutes=15):
            cursor.execute("""
                UPDATE login_attempts
                SET failed_attempts = 1,
                    first_failed_at = %s,
                    last_failed_at = %s,
                    locked_until = NULL
                WHERE email = %s
            """, (now, now, email))
            db.commit()
            return False

        failed_attempts = int(record["failed_attempts"] or 0) + 1
        locked_until = None
        if failed_attempts >= 5:
            locked_until = now + timedelta(minutes=15)

        cursor.execute("""
            UPDATE login_attempts
            SET failed_attempts = %s,
                last_failed_at = %s,
                locked_until = %s
            WHERE email = %s
        """, (failed_attempts, now, locked_until, email))
        db.commit()
        return failed_attempts >= 5
    finally:
        if cursor:
            cursor.close()


def clear_failed_logins(email):
    ensure_auth_security_tables()
    cursor = None
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM login_attempts WHERE email = %s", (email,))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        if cursor:
            cursor.close()


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "").strip().lower()

        form_data = {
            "full_name": full_name,
            "email": email,
            "mobile": mobile,
            "role": role
        }

        def render_error(message):
            return render_template(
                "auth/register.html",
                error=message,
                form_data=form_data
            )

        if not full_name or not email or not mobile or not password or not confirm_password:
            return render_error("Please fill all required fields.")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_error("Please enter a valid email address.")

        if not re.fullmatch(r"\d{10}", mobile):
            return render_error("Mobile number must contain exactly 10 digits.")

        if role not in ["buyer", "seller", "mentor"]:
            return render_error("Invalid role selected.")

        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)
        ):
            return render_error(
                "Password must contain at least 8 characters, one uppercase letter, "
                "one lowercase letter, and one number."
            )

        if password != confirm_password:
            return render_error("Passwords do not match.")

        cursor = None
        try:
            ensure_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("""
                SELECT id
                FROM users
                WHERE email = %s OR mobile = %s
                LIMIT 1
            """, (email, mobile))

            if cursor.fetchone():
                return render_error(
                    "An account with this email or mobile number already exists."
                )

            if not google_oauth_enabled():
                return render_error(
                    "Google registration is not configured yet. Please configure "
                    "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first."
                )

            session["pending_registration"] = {
                "full_name": full_name,
                "email": email,
                "mobile": mobile,
                "password_hash": generate_password_hash(password),
                "role": role
            }
            return redirect(url_for("register_google"))

        except Exception:
            current_app.logger.exception("Registration preparation failed.")
            return render_error(
                "Unable to start registration right now. Please try again."
            )
        finally:
            if cursor:
                cursor.close()

    return render_template(
        "auth/register.html",
        error=None,
        message=None,
        form_data={}
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        cursor = None

        if not email or not password:
            return render_template(
                "auth/login.html",
                error="Please enter your email and password.",
                email=email
            )

        if login_locked(email):
            return render_template(
                "auth/login.html",
                error="Your account has been temporarily locked for 15 minutes due to repeated failed login attempts.",
                email=email
            )

        try:
            ensure_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, full_name, email, password, role
                FROM users
                WHERE email = %s
            """, (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user["password"], password):
                register_failed_login(email)
                return render_template(
                    "auth/login.html",
                    error="Incorrect email or password.",
                    email=email
                )

            clear_failed_logins(email)
            establish_login_session(user)
            return redirect_after_login(user)

        except Exception:
            current_app.logger.exception("Password sign-in failed.")
            return render_template(
                "auth/login.html",
                error="Sign-in could not be completed. Please try again.",
                email=email
            )
        finally:
            if cursor:
                cursor.close()

    message = None
    if request.args.get("registered") == "1":
        message = "Account created successfully. You can now log in."

    return render_template("auth/login.html", message=message)


# =========================================================
# GOOGLE OAUTH
# =========================================================

def google_oauth_enabled():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _google_authorize(mode):
    if not google_oauth_enabled():
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your environment.",
            email=""
        )

    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state
    session["google_oauth_mode"] = mode

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(auth_url)


@app.route("/login/google")
def login_google():
    return _google_authorize("login")


@app.route("/register/google")
def register_google():
    pending = session.get("pending_registration")
    if not pending:
        return redirect(url_for("register"))
    return _google_authorize("register")


@app.route("/google/callback")
def google_callback():
    expected_state = session.pop("google_oauth_state", "")
    mode = session.pop("google_oauth_mode", "login")
    returned_state = request.args.get("state", "")

    if not expected_state or not returned_state or not hmac.compare_digest(
        expected_state,
        returned_state
    ):
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be verified. Please try again.",
            email=""
        ), 400

    error_message = request.args.get("error")
    if error_message:
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication was cancelled or could not be completed.",
            email=""
        )

    code = request.args.get("code")
    if not code:
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication failed: no authorization code returned.",
            email=""
        )

    try:
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            },
            timeout=15
        )
        token_response.raise_for_status()

        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise RuntimeError("Google did not return an access token.")

        userinfo_response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15
        )
        userinfo_response.raise_for_status()

        userinfo = userinfo_response.json()
        if userinfo.get("email_verified") is not True:
            raise RuntimeError("Google did not verify the email address.")

        google_email = (userinfo.get("email") or "").strip().lower()
        if not google_email:
            raise RuntimeError("Google did not return an email address.")

    except requests.RequestException:
        current_app.logger.exception("Google HTTP request failed.")
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=""
        ), 502
    except Exception:
        current_app.logger.exception("Google profile validation failed.")
        if mode == "register":
            session.pop("pending_registration", None)
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=""
        ), 400

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, full_name, email, password, role
            FROM users
            WHERE email = %s
        """, (google_email,))
        user = cursor.fetchone()

        if mode == "register":
            pending = session.pop("pending_registration", None)
            if not pending:
                return redirect(url_for("register"))

            if pending["email"] != google_email:
                return render_template(
                    "auth/register.html",
                    error=(
                        "The Google email does not match the email entered in "
                        "the registration form. Please use the same email."
                    ),
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                ), 400

            if user:
                return render_template(
                    "auth/register.html",
                    error="An account with this Google email already exists. Please log in instead.",
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                )

            cursor.execute("""
                SELECT id
                FROM users
                WHERE mobile = %s
                LIMIT 1
            """, (pending["mobile"],))
            if cursor.fetchone():
                return render_template(
                    "auth/register.html",
                    error="An account with this mobile number already exists.",
                    form_data={
                        "full_name": pending["full_name"],
                        "email": pending["email"],
                        "mobile": pending["mobile"],
                        "role": pending["role"]
                    }
                )

            cursor.execute("""
                INSERT INTO users (full_name, email, mobile, password, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                pending["full_name"],
                google_email,
                pending["mobile"],
                pending["password_hash"],
                pending["role"]
            ))
            user_id = cursor.lastrowid

            if pending["role"] == "seller":
                cursor.execute("""
                    INSERT INTO seller_approvals (seller_id, status)
                    VALUES (%s, 'pending')
                """, (user_id,))

            db.commit()

            cursor.execute("""
                SELECT id, full_name, email, password, role
                FROM users
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()

        else:
            if not user:
                return render_template(
                    "auth/login.html",
                    error="No account was found for this Google email. Please register first.",
                    email=google_email
                )

        clear_failed_logins(google_email)
        establish_login_session(user)
        return redirect_after_login(user)

    except IntegrityError:
        db.rollback()
        current_app.logger.exception("Google account creation conflict.")
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="An account with these details already exists. Please try again.",
            email=google_email
        ), 409
    except Exception:
        db.rollback()
        current_app.logger.exception("Google authentication database operation failed.")
        template = "auth/register.html" if mode == "register" else "auth/login.html"
        return render_template(
            template,
            error="Google authentication could not be completed. Please try again.",
            email=google_email
        ), 500
    finally:
        if cursor:
            cursor.close()


# =========================================================
# LOGIN SESSION + ROLE REDIRECT
# =========================================================

def establish_login_session(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]
    session["role"] = user["role"]


def redirect_after_login(user):
    role = (user.get("role") or "").strip().lower()

    if role == "seller":
        if not seller_has_access(user["id"]):
            return redirect(url_for("seller_pending_approval"))
        return redirect(url_for("seller_dashboard"))
    if role == "buyer":
        return redirect(url_for("buyer_dashboard"))
    if role == "mentor":
        return redirect(url_for("mentor_dashboard"))
    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    session.clear()
    return redirect(url_for("login"))


# =========================================================
# ACCESS CHECKS
# =========================================================

def buyer_required():
    return (
        "user_id" in session
        and session.get("role") == "buyer"
    )


def seller_required():
    if "user_id" not in session or session.get("role") != "seller":
        return redirect(url_for("login"))
    if not seller_has_access(session["user_id"]):
        return redirect(url_for("seller_pending_approval"))
    return None


def seller_has_access(seller_id):
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT status, account_status
            FROM seller_approvals
            WHERE seller_id = %s
            LIMIT 1
        """, (seller_id,))
        approval = cursor.fetchone()
        return bool(
            approval
            and approval["status"] == "approved"
            and approval["account_status"] == "active"
        )
    except Exception:
        current_app.logger.exception("Unable to verify seller account access.")
        abort(503, description="Seller access could not be verified. Please try again later.")
    finally:
        if cursor:
            cursor.close()


@app.route("/seller/pending-approval")
def seller_pending_approval():
    if "user_id" not in session or session.get("role") != "seller":
        return redirect(url_for("login"))

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT status, account_status, review_note
            FROM seller_approvals
            WHERE seller_id = %s
            LIMIT 1
        """, (session["user_id"],))
        approval = cursor.fetchone() or {
            "status": "pending",
            "account_status": "active",
            "review_note": None
        }
        if approval["status"] == "approved" and approval["account_status"] == "active":
            return redirect(url_for("seller_dashboard"))
        return render_template("seller/pending.html", approval=approval)
    except Exception:
        current_app.logger.exception("Unable to load seller approval status.")
        return "Unable to load seller approval status.", 500
    finally:
        if cursor:
            cursor.close()


def admin_required():
    return (
        "user_id" in session
        and session.get("role") == "admin"
    )


def mentor_required():
    return (
        "user_id" in session
        and session.get("role") == "mentor"
    )


def ensure_mentor_tables():
    ensure_db_connection()
    cursor = None
    try:
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mentor_profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                expertise VARCHAR(255) NULL,
                bio TEXT NULL,
                experience_years INT NOT NULL DEFAULT 0,
                availability VARCHAR(255) NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'pending',
                review_note TEXT NULL,
                reviewed_by INT NULL,
                reviewed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_mentor_profile_user (user_id),
                INDEX idx_mentor_profile_status (status),
                INDEX idx_mentor_profile_expertise (expertise),
                CONSTRAINT fk_mentor_profile_user
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                CONSTRAINT fk_mentor_profile_reviewer
                    FOREIGN KEY (reviewed_by) REFERENCES users(id)
                    ON DELETE SET NULL
            )
        """)
        db.commit()
    finally:
        if cursor:
            cursor.close()


# =========================================================
# BUYER PORTAL ROUTES
# =========================================================

@app.route("/buyer/dashboard")
def buyer_dashboard():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        query = """
            SELECT products.id, products.name, products.description, products.price,
                   products.stock, products.image_url, categories.name AS category_name,
                   users.full_name AS seller_name
            FROM products
            INNER JOIN categories ON products.category_id = categories.id
            INNER JOIN users ON products.seller_id = users.id
            WHERE products.status = 'active' AND products.stock > 0
        """
        params = []
        if search:
            query += " AND (products.name LIKE %s OR products.description LIKE %s)"
            value = "%" + search + "%"
            params.extend([value, value])
        if category:
            query += " AND categories.name = %s"
            params.append(category)
        query += " ORDER BY products.created_at DESC"
        cursor.execute(query, tuple(params))
        products = cursor.fetchall()
        return render_template("buyer/dashboard.html", products=products)
    except Exception as e:
        return _internal_error_response(e, "Unable to load buyer dashboard.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/products")
def buyer_products():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        query = """
            SELECT products.id, products.name, products.description, products.price,
                   products.stock, products.image_url, categories.name AS category_name,
                   users.full_name AS seller_name
            FROM products
            INNER JOIN categories ON products.category_id = categories.id
            INNER JOIN users ON products.seller_id = users.id
            WHERE products.status = 'active' AND products.stock > 0
        """
        params = []
        if search:
            query += " AND (products.name LIKE %s OR products.description LIKE %s)"
            value = "%" + search + "%"
            params.extend([value, value])
        if category:
            query += " AND categories.name = %s"
            params.append(category)
        query += " ORDER BY products.created_at DESC"
        cursor.execute(query, tuple(params))
        products = cursor.fetchall()
        cursor.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cursor.fetchall()
        return render_template(
            "buyer/products.html",
            products=products,
            categories=categories,
            search=search,
            selected_category=category
        )
    except Exception as e:
        return _internal_error_response(e, "Unable to load marketplace.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/product/<int:product_id>")
def buyer_product_details(product_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT products.id, products.name, products.description, products.price,
                   products.stock, products.image_url, categories.name AS category_name,
                   users.full_name AS seller_name
            FROM products
            INNER JOIN categories ON products.category_id = categories.id
            INNER JOIN users ON products.seller_id = users.id
            WHERE products.id = %s AND products.status = 'active'
        """, (product_id,))
        product = cursor.fetchone()
        if not product:
            return "Product not found.", 404
        return render_template("buyer/product_details.html", product=product)
    except Exception as e:
        return _internal_error_response(e, "Unable to load product details.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/cart")
def buyer_cart():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        buyer_id = session["user_id"]
        cursor.execute("SELECT id FROM cart WHERE buyer_id = %s", (buyer_id,))
        cart = cursor.fetchone()
        items = []
        total = 0
        if cart:
            cursor.execute("""
                SELECT cart_items.id AS cart_item_id, cart_items.quantity,
                       products.id AS product_id, products.name, products.price,
                       products.stock, products.image_url,
                       (cart_items.quantity * products.price) AS subtotal
                FROM cart_items
                INNER JOIN products ON cart_items.product_id = products.id
                WHERE cart_items.cart_id = %s
                ORDER BY cart_items.id DESC
            """, (cart["id"],))
            items = cursor.fetchall()
            total = sum(float(item["subtotal"] or 0) for item in items)
        return render_template("buyer/cart.html", items=items, total=total)
    except Exception as e:
        return _internal_error_response(e, "Unable to load cart.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/cart/add/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        buyer_id = session["user_id"]
        cursor.execute("SELECT id, stock, status FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        if not product or product["status"] != "active" or product["stock"] <= 0:
            return "This product is currently unavailable.", 409

        cursor.execute("SELECT id FROM cart WHERE buyer_id = %s", (buyer_id,))
        cart = cursor.fetchone()
        if not cart:
            cursor.execute("INSERT INTO cart (buyer_id) VALUES (%s)", (buyer_id,))
            cart_id = cursor.lastrowid
        else:
            cart_id = cart["id"]

        cursor.execute("SELECT id, quantity FROM cart_items WHERE cart_id = %s AND product_id = %s", (cart_id, product_id))
        existing = cursor.fetchone()
        if existing:
            new_quantity = existing["quantity"] + 1
            if new_quantity > product["stock"]:
                return "You cannot add more than available stock.", 409
            cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (new_quantity, existing["id"]))
        else:
            cursor.execute("INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (%s, %s, 1)", (cart_id, product_id))
        db.commit()
        return redirect(url_for("buyer_cart"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to add product to cart.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/cart/update/<int:cart_item_id>", methods=["POST"])
def update_cart(cart_item_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        quantity = int(request.form.get("quantity", 1))
        if quantity < 1:
            return "Quantity must be at least 1.", 400

        cursor.execute("""
            SELECT cart_items.id, products.stock
            FROM cart_items
            INNER JOIN cart ON cart_items.cart_id = cart.id
            INNER JOIN products ON cart_items.product_id = products.id
            WHERE cart_items.id = %s AND cart.buyer_id = %s
        """, (cart_item_id, session["user_id"]))
        item = cursor.fetchone()
        if not item:
            return "Cart item not found.", 404
        if quantity > item["stock"]:
            return "Quantity cannot be greater than available stock.", 409

        cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (quantity, cart_item_id))
        db.commit()
        return redirect(url_for("buyer_cart"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to update cart.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/cart/remove/<int:cart_item_id>", methods=["POST"])
def remove_from_cart(cart_item_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor()
        cursor.execute("""
            DELETE cart_items FROM cart_items
            INNER JOIN cart ON cart_items.cart_id = cart.id
            WHERE cart_items.id = %s AND cart.buyer_id = %s
        """, (cart_item_id, session["user_id"]))
        db.commit()
        return redirect(url_for("buyer_cart"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to remove item from cart.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/wishlist")
def buyer_wishlist():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT wishlist.id AS wishlist_id, products.id AS product_id,
                   products.name, products.description, products.price,
                   products.stock, products.image_url, categories.name AS category_name,
                   users.full_name AS seller_name
            FROM wishlist
            INNER JOIN products ON wishlist.product_id = products.id
            INNER JOIN categories ON products.category_id = categories.id
            INNER JOIN users ON products.seller_id = users.id
            WHERE wishlist.buyer_id = %s
            ORDER BY wishlist.id DESC
        """, (session["user_id"],))
        products = cursor.fetchall()
        return render_template("buyer/wishlist.html", products=products)
    except Exception as e:
        return _internal_error_response(e, "Unable to load wishlist.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/wishlist/add/<int:product_id>", methods=["POST"])
def add_to_wishlist(product_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor()
        cursor.execute("INSERT IGNORE INTO wishlist (buyer_id, product_id) VALUES (%s, %s)", (session["user_id"], product_id))
        db.commit()
        return redirect(url_for("buyer_wishlist"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to add to wishlist.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/wishlist/remove/<int:wishlist_id>", methods=["POST"])
def remove_from_wishlist(wishlist_id):
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor()
        cursor.execute("DELETE FROM wishlist WHERE id = %s AND buyer_id = %s", (wishlist_id, session["user_id"]))
        db.commit()
        return redirect(url_for("buyer_wishlist"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to remove from wishlist.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/orders")
def buyer_orders():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT orders.id, orders.total_amount, orders.status, orders.shipping_address,
                   orders.created_at, payments.payment_status, payments.payment_method
            FROM orders
            LEFT JOIN payments ON orders.id = payments.order_id
            WHERE orders.buyer_id = %s
            ORDER BY orders.created_at DESC
        """, (session["user_id"],))
        orders = cursor.fetchall()
        for order in orders:
            cursor.execute("""
                SELECT order_items.quantity, order_items.unit_price, order_items.subtotal,
                       products.name, products.image_url
                FROM order_items
                INNER JOIN products ON order_items.product_id = products.id
                WHERE order_items.order_id = %s
            """, (order["id"],))
            order["items"] = cursor.fetchall()
        return render_template("buyer/orders.html", orders=orders)
    except Exception as e:
        return _internal_error_response(e, "Unable to load orders.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/checkout", methods=["POST"])
def checkout():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        buyer_id = session["user_id"]
        address_line = request.form.get("address_line", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()

        if not address_line or not city or not state or not pincode:
            return "Please enter complete shipping address."
        if not re.fullmatch(r"\d{6}", pincode):
            return "Pincode must contain exactly 6 digits."

        cursor.execute("SELECT id FROM cart WHERE buyer_id = %s", (buyer_id,))
        cart = cursor.fetchone()
        if not cart:
            return "Your cart is empty."

        cursor.execute("""
            SELECT cart_items.product_id, cart_items.quantity, products.name,
                   products.price, products.stock, products.seller_id, products.status
            FROM cart_items
            INNER JOIN products ON cart_items.product_id = products.id
            WHERE cart_items.cart_id = %s
            FOR UPDATE
        """, (cart["id"],))
        items = cursor.fetchall()
        if not items:
            return "Your cart is empty."

        total = Decimal("0.00")
        for item in items:
            if item["status"] != "active":
                return f"{item['name']} is no longer available."
            if item["quantity"] > item["stock"]:
                return f"Not enough stock for {item['name']}."
            total += Decimal(item["price"]) * item["quantity"]

        shipping_address = f"{address_line}, {city}, {state} - {pincode}"

        cursor.execute("""
            INSERT INTO orders (buyer_id, total_amount, status, shipping_address)
            VALUES (%s, %s, 'pending', %s)
        """, (buyer_id, total, shipping_address))
        order_id = cursor.lastrowid

        cursor.execute("INSERT INTO order_status_history (order_id, status, note) VALUES (%s, 'pending', 'Order placed with Cash on Delivery')", (order_id,))

        for item in items:
            subtotal = Decimal(item["price"]) * item["quantity"]
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, seller_id, quantity, unit_price, subtotal)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (order_id, item["product_id"], item["seller_id"], item["quantity"], item["price"], subtotal))

            cursor.execute("""
                UPDATE products SET stock = stock - %s WHERE id = %s AND stock >= %s
            """, (item["quantity"], item["product_id"], item["quantity"]))

        cursor.execute("""
            INSERT INTO payments (order_id, payment_method, amount, payment_status)
            VALUES (%s, 'Cash on Delivery', %s, 'pending')
        """, (order_id, total))

        cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart["id"],))
        db.commit()

        flash("Order placed successfully.", "success")
        return redirect(url_for("buyer_orders"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Checkout failed.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/profile", methods=["GET", "POST"])
def buyer_profile():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            mobile = request.form.get("mobile", "").strip()
            if not full_name:
                return "Full name is required."
            if not re.fullmatch(r"\d{10}", mobile):
                return "Mobile number must contain exactly 10 digits."
            cursor.execute("UPDATE users SET full_name = %s, mobile = %s WHERE id = %s AND role = 'buyer'", (full_name, mobile, session["user_id"]))
            db.commit()
            session["full_name"] = full_name
            return redirect(url_for("buyer_profile"))

        cursor.execute("SELECT id, full_name, email, mobile FROM users WHERE id = %s AND role = 'buyer'", (session["user_id"],))
        user = cursor.fetchone()
        cursor.execute("SELECT id, address_line, city, state, pincode, is_default FROM buyer_addresses WHERE buyer_id = %s ORDER BY is_default DESC, id DESC", (session["user_id"],))
        addresses = cursor.fetchall()
        return render_template("buyer/profile.html", user=user, addresses=addresses)
    except Exception as e:
        return _internal_error_response(e, "Unable to load profile.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/address/add", methods=["POST"])
def add_buyer_address():
    if not buyer_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor()
        address_line = request.form.get("address_line", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()

        if not address_line or not city or not state or not pincode:
            return "Please fill all address fields."
        if not re.fullmatch(r"\d{6}", pincode):
            return "Pincode must contain exactly 6 digits."

        cursor.execute("""
            INSERT INTO buyer_addresses (buyer_id, address_line, city, state, pincode)
            VALUES (%s, %s, %s, %s, %s)
        """, (session["user_id"], address_line, city, state, pincode))
        db.commit()
        return redirect(url_for("buyer_profile"))
    except Exception as e:
        db.rollback()
        return _internal_error_response(e, "Unable to save address.")
    finally:
        if cursor:
            cursor.close()


@app.route("/buyer/custom-requests", methods=["GET", "POST"], endpoint="buyer_custom_requests")
@app.route("/buyer/custom-request", methods=["GET", "POST"])
def buyer_custom_request():
    if not buyer_required():
        return redirect(url_for("login"))

    if request.method == "POST":
        cursor = None
        try:
            ensure_db_connection()
            cursor = db.cursor()
            product_name = request.form.get("product_name", "").strip()
            description = request.form.get("description", "").strip()
            budget = request.form.get("budget", "").strip()

            if not product_name or len(product_name) > 150:
                return "Product name is required and must be 150 characters or fewer.", 400
            if not description or len(description) > 5000:
                return "Product description is required and must be 5,000 characters or fewer.", 400

            budget_value = None
            if budget:
                try:
                    budget_value = Decimal(budget)
                except (InvalidOperation, ValueError):
                    return "Budget must be a valid number.", 400

            cursor.execute("""
                INSERT INTO custom_requests (buyer_id, product_name, description, budget, status)
                VALUES (%s, %s, %s, %s, 'pending')
            """, (session["user_id"], product_name, description, budget_value))
            db.commit()
            flash("Custom request submitted successfully.", "success")
            return redirect(url_for("buyer_custom_requests"))
        except Exception as e:
            db.rollback()
            return _internal_error_response(e, "Unable to submit custom request.")
        finally:
            if cursor:
                cursor.close()

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, product_name, description, budget, status,
                   quotation_amount, seller_response, created_at
            FROM custom_requests
            WHERE buyer_id = %s
            ORDER BY created_at DESC, id DESC
        """, (session["user_id"],))
        requests_list = cursor.fetchall()
        return render_template("buyer/custom_requests.html", requests=requests_list)
    except Exception as e:
        return _internal_error_response(e, "Unable to load custom requests.")
    finally:
        if cursor:
            cursor.close()


# =========================================================
# SELLER PORTAL ROUTES
# =========================================================

@app.route("/seller/dashboard")
def seller_dashboard():
    auth_check = seller_required()
    if auth_check:
        return auth_check

    cursor = None
    total_products = 0
    total_revenue = 0
    total_orders = 0
    total_sales = 0

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        seller_id = session["user_id"]

        cursor.execute("SELECT COUNT(*) AS total FROM products WHERE seller_id = %s", (seller_id,))
        result = cursor.fetchone()
        if result:
            total_products = int(result["total"] or 0)

        cursor.execute("""
            SELECT COUNT(DISTINCT order_items.order_id) AS total_orders,
                   COALESCE(SUM(order_items.quantity), 0) AS total_sales,
                   COALESCE(SUM(order_items.subtotal), 0) AS total_revenue
            FROM order_items
            INNER JOIN orders ON order_items.order_id = orders.id
            INNER JOIN payments ON payments.order_id = orders.id AND payments.payment_status = 'paid'
            WHERE order_items.seller_id = %s AND orders.status NOT IN ('cancelled', 'returned')
        """, (seller_id,))
        result = cursor.fetchone()
        if result:
            total_orders = int(result["total_orders"] or 0)
            total_sales = int(result["total_sales"] or 0)
            total_revenue = float(result["total_revenue"] or 0)
    except Exception as e:
        print("Dashboard error:", e)
    finally:
        if cursor:
            cursor.close()

    return render_template(
        "seller/dashboard.html",
        seller_name=session.get("full_name", "Seller"),
        total_products=total_products,
        total_revenue=total_revenue,
        total_orders=total_orders,
        total_sales=total_sales
    )


@app.route("/seller/profile", methods=["GET", "POST"])
def seller_profile():
    auth_check = seller_required()
    if auth_check:
        return auth_check

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        seller_id = session["user_id"]

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            mobile = request.form.get("mobile", "").strip()
            if not full_name:
                return "Full name is required.", 400
            if not re.fullmatch(r"\d{10}", mobile):
                return "Mobile number must contain exactly 10 digits.", 400
            cursor.execute("UPDATE users SET full_name = %s, mobile = %s WHERE id = %s AND role = 'seller'", (full_name, mobile, seller_id))
            db.commit()
            session["full_name"] = full_name
            return redirect(url_for("seller_profile"))

        cursor.execute("SELECT id, full_name, email, mobile FROM users WHERE id = %s AND role = 'seller'", (seller_id,))
        user = cursor.fetchone()
        return render_template("seller/profile.html", user=user)
    except Exception:
        db.rollback()
        return "Unable to load profile.", 500
    finally:
        if cursor:
            cursor.close()


@app.route("/seller/products")
def seller_products():
    auth_check = seller_required()
    if auth_check:
        return auth_check

    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        seller_id = session["user_id"]
        cursor.execute("""
            SELECT products.id, products.name, products.description, products.price,
                   products.stock, products.image_url, products.status, products.created_at,
                   categories.name AS category_name
            FROM products
            INNER JOIN categories ON products.category_id = categories.id
            WHERE products.seller_id = %s
            ORDER BY products.created_at DESC
        """, (seller_id,))
        products = cursor.fetchall()
        return render_template("seller/products.html", products=products)
    except Exception as e:
        return _internal_error_response(e, "Unable to load products.")
    finally:
        if cursor:
            cursor.close()


@app.route("/seller/products/add", methods=["GET", "POST"])
def add_product():
    auth_check = seller_required()
    if auth_check:
        return auth_check

    cursor = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category_id = request.form.get("category_id", "").strip()
        description = request.form.get("description", "").strip()
        price = request.form.get("price", "").strip()
        stock = request.form.get("stock", "").strip()
        image_url = request.form.get("image_url", "").strip()
        status = request.form.get("status", "active").strip().lower()

        if not name or not category_id or not description or not price or not stock:
            return "Please fill all required product fields."

        try:
            category_value = int(category_id)
            price_value = float(price)
            stock_value = int(stock)
        except ValueError:
            return "Invalid number format for price, stock, or category."

        if price_value <= 0 or stock_value < 0:
            return "Price must be positive and stock cannot be negative."

        try:
            ensure_db_connection()
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO products (seller_id, category_id, name, description, price, stock, image_url, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (session["user_id"], category_value, name, description, price_value, stock_value, image_url, status))
            db.commit()
            return redirect(url_for("seller_products"))
        except Exception as e:
            db.rollback()
            return _internal_error_response(e, "Unable to add product.")
        finally:
            if cursor:
                cursor.close()

    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cursor.fetchall()
        return render_template("seller/add_product.html", categories=categories)
    except Exception as e:
        return _internal_error_response(e, "Unable to load categories.")
    finally:
        if cursor:
            cursor.close()


# =========================================================
# ADMIN PORTAL ROUTES
# =========================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_required():
        return redirect(url_for("login"))
    cursor = None
    try:
        ensure_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total_users FROM users")
        total_users = cursor.fetchone()["total_users"] or 0

        cursor.execute("SELECT COUNT(*) AS total_sellers FROM users WHERE role = 'seller'")
        total_sellers = cursor.fetchone()["total_sellers"] or 0

        cursor.execute("SELECT COUNT(*) AS total_buyers FROM users WHERE role = 'buyer'")
        total_buyers = cursor.fetchone()["total_buyers"] or 0

        cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
        total_orders = cursor.fetchone()["total_orders"] or 0

        return render_template(
            "admin/dashboard.html",
            total_users=total_users,
            total_sellers=total_sellers,
            total_buyers=total_buyers,
            total_orders=total_orders
        )
    except Exception as e:
        return _internal_error_response(e, "Unable to load admin dashboard.")
    finally:
        if cursor:
            cursor.close()


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "GET":
        return render_template("auth/logout.html")
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}
    )
