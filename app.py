"""
DIY Investing — Full Stack Backend v7
======================================
- PostgreSQL for users, subscriptions, watchlists, prop research
- JWT auth + Google OAuth
- Razorpay direct payment links
- Admin dashboard API
- yfinance for stock data (INR native)
- Grok API for sentiment analysis
"""

import os, time, math, logging, hashlib, secrets, json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, redirect, url_for, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt as pyjwt
import requests
import yfinance as yf

# ═══════ CONFIG ═══════
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization"], "expose_headers": ["Content-Type"], "supports_credentials": True}})

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///diy.db")
# Fix Render's postgres:// vs postgresql://
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres://", "postgresql+psycopg://", 1)
elif app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

PORT = int(os.environ.get("PORT", 10000))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET    = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
GROK_API_KEY = os.environ.get("GROK_API_KEY", "")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "").split(",")  # comma-separated
SMTP_HOST    = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER    = os.environ.get("SMTP_USER", "")          # your Gmail
SMTP_PASS    = os.environ.get("SMTP_PASS", "")          # App-password
FROM_NAME    = os.environ.get("FROM_NAME", "DIY Investing")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://diyinvesting.in")

# Razorpay Payment Links (set these in environment variables)
RAZORPAY_MONTHLY_LINK = os.environ.get("RAZORPAY_MONTHLY_LINK", "")
RAZORPAY_QUARTERLY_LINK = os.environ.get("RAZORPAY_QUARTERLY_LINK", "")
RAZORPAY_YEARLY_LINK = os.environ.get("RAZORPAY_YEARLY_LINK", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("diy")


# ═══════ DATABASE MODELS ═══════

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), default="")
    phone = db.Column(db.String(20), default="")
    password_hash = db.Column(db.String(255), default="")  # empty for Google-only users
    google_id = db.Column(db.String(255), default="")
    avatar_url = db.Column(db.String(500), default="")
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    # Subscription
    plan = db.Column(db.String(20), default="free")  # free, trial, monthly, quarterly, yearly
    plan_expires = db.Column(db.DateTime, nullable=True)
    razorpay_payment_id = db.Column(db.String(255), default="")
    razorpay_order_id = db.Column(db.String(255), default="")
    total_paid = db.Column(db.Float, default=0)
    # Engagement
    login_count = db.Column(db.Integer, default=0)
    stocks_analyzed = db.Column(db.Integer, default=0)

    watchlist = db.relationship("WatchlistItem", backref="user", lazy=True, cascade="all, delete-orphan")
    payments = db.relationship("Payment", backref="user", lazy=True, cascade="all, delete-orphan")

    def is_pro(self):
        if self.is_admin:
            return True
        if self.plan == "free":
            return False
        if self.plan == "trial":
            return self.plan_expires and datetime.utcnow() < self.plan_expires
        return self.plan_expires and datetime.utcnow() < self.plan_expires

    def days_left(self):
        if not self.plan_expires:
            return 0
        d = (self.plan_expires - datetime.utcnow()).days
        return max(0, d)

    def to_dict(self, include_private=False):
        d = {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "avatar": self.avatar_url,
            "isAdmin": self.is_admin,
            "plan": self.plan,
            "isPro": self.is_pro(),
            "daysLeft": self.days_left(),
            "planExpires": self.plan_expires.isoformat() if self.plan_expires else None,
            "createdAt": self.created_at.isoformat(),
            "hasGoogle": bool(self.google_id),
            "hasPassword": bool(self.password_hash),
        }
        if include_private:
            d["loginCount"] = self.login_count
            d["stocksAnalyzed"] = self.stocks_analyzed
            d["totalPaid"] = self.total_paid
            d["lastLogin"] = self.last_login.isoformat() if self.last_login else None
        return d


class WatchlistItem(db.Model):
    __tablename__ = "watchlist"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    symbol = db.Column(db.String(30), nullable=False)
    name = db.Column(db.String(255), default="")
    sector = db.Column(db.String(100), default="")
    cmp = db.Column(db.Float, default=0)
    mcap = db.Column(db.Float, default=0)
    implied_growth = db.Column(db.Float, nullable=True)
    intrinsic_value = db.Column(db.Float, default=0)
    gap = db.Column(db.Float, default=0)
    # User's assumptions
    exit_pe = db.Column(db.Float, default=20)
    discount_rate = db.Column(db.Float, default=15)
    forecast_years = db.Column(db.Integer, default=10)
    expected_cagr = db.Column(db.Float, default=15)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "sym": self.symbol,
            "name": self.name,
            "sec": self.sector,
            "cmp": self.cmp,
            "mcap": self.mcap,
            "ig": self.implied_growth,
            "iv": self.intrinsic_value,
            "gap": self.gap,
            "inputs": {
                "pe": self.exit_pe,
                "dr": self.discount_rate,
                "fy": self.forecast_years,
                "ec": self.expected_cagr,
            },
            "addedAt": self.added_at.isoformat(),
        }


class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    razorpay_payment_id = db.Column(db.String(255), default="")
    razorpay_order_id = db.Column(db.String(255), default="")
    razorpay_signature = db.Column(db.String(500), default="")
    amount = db.Column(db.Float, default=0)
    plan = db.Column(db.String(20), default="")
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PropResearch(db.Model):
    __tablename__ = "prop_research"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    symbol = db.Column(db.String(30), nullable=False)
    sector = db.Column(db.String(100), default="")
    thesis = db.Column(db.Text, default="")  # Main investment thesis
    target_cagr = db.Column(db.Float, default=25)
    time_horizon = db.Column(db.String(20), default="1-3 years")
    entry_price = db.Column(db.Float, default=0)
    target_price = db.Column(db.Float, default=0)
    risks = db.Column(db.Text, default="")  # Key risks
    catalysts = db.Column(db.Text, default="")  # Key catalysts
    content = db.Column(db.Text, default="")  # Full HTML content
    published_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    views = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "symbol": self.symbol,
            "sector": self.sector,
            "thesis": self.thesis,
            "targetCagr": self.target_cagr,
            "timeHorizon": self.time_horizon,
            "entryPrice": self.entry_price,
            "targetPrice": self.target_price,
            "risks": self.risks,
            "catalysts": self.catalysts,
            "content": self.content,
            "publishedAt": self.published_at.isoformat(),
            "views": self.views,
        }


# ═══════ AUTH HELPERS ═══════

def hash_password(pwd):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 200000)
    return salt + ":" + h.hex()

def verify_password(pwd, stored):
    if not stored or ":" not in stored:
        return False
    salt, h = stored.split(":", 1)
    h2 = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 200000)
    return h == h2.hex()

def make_token(user):
    payload = {
        "uid": user.id,
        "email": user.email,
        "admin": user.is_admin,
        "exp": datetime.utcnow() + timedelta(days=30),
    }
    return pyjwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            log.warning(f"[AUTH] No token for {request.path}")
            return jsonify({"error": "Login required"}), 401
        try:
            data = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user = User.query.get(data["uid"])
            if not g.user:
                return jsonify({"error": "User not found"}), 401
            return f(*args, **kwargs)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            log.error(f"[AUTH ERROR] {e}")
            return jsonify({"error": "Invalid token"}), 401
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or not g.user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ═══════ CACHE ═══════
cache = {}
SEARCH_TTL = 3600
QUOTE_TTL = 300
FIN_TTL = 86400

def cached(key, ttl):
    if key in cache:
        val, exp = cache[key]
        if time.time() < exp:
            return val
        del cache[key]
    return None

def set_cache(key, val):
    cache[key] = (val, time.time() + QUOTE_TTL)


# ═══════ AUTH ROUTES ═══════

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not name:
        return jsonify({"error": "Name is required"}), 400

    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "Email already registered"}), 400

    u = User(
        email=email,
        name=name,
        phone=phone,
        password_hash=hash_password(password),
        plan="trial",
        plan_expires=datetime.utcnow() + timedelta(days=2),
        is_admin=(email in ADMIN_EMAILS),
    )
    db.session.add(u)
    db.session.commit()
    log.info(f"[SIGNUP] {email}")
    try:
        welcome_email(u)
    except Exception as e:
        log.warning(f"[SIGNUP EMAIL] {e}")
    return jsonify({"token": make_token(u), "user": u.to_dict()})


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    u = User.query.filter_by(email=email).first()
    if not u or not verify_password(password, u.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    u.login_count = (u.login_count or 0) + 1
    u.last_login = datetime.utcnow()
    db.session.commit()
    log.info(f"[LOGIN] {email}")
    return jsonify({"token": make_token(u), "user": u.to_dict()})


@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = request.json or {}
    credential = data.get("credential")
    if not credential:
        return jsonify({"error": "No credential"}), 400

    try:
        # Use Google's tokeninfo endpoint with retry logic
        info = None
        last_error = None
        
        for attempt in range(3):  # retry up to 3 times
            try:
                r = requests.get(
                    f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}",
                    timeout=10
                )
                if r.status_code == 200:
                    info = r.json()
                    break
                else:
                    # Try alternative endpoint
                    r2 = requests.get(
                        f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={credential}",
                        timeout=10
                    )
                    if r2.status_code == 200:
                        info = r2.json()
                        break
                    last_error = f"Status {r.status_code}: {r.text[:100]}"
            except Exception as e:
                last_error = str(e)
                time.sleep(0.5)
        
        if not info:
            log.error(f"[GOOGLE] Token validation failed after 3 attempts: {last_error}")
            return jsonify({"error": "Could not verify Google token. Please try again."}), 400

        # Verify audience if client ID is configured
        aud = info.get("aud", "")
        if GOOGLE_CLIENT_ID and aud and aud != GOOGLE_CLIENT_ID:
            log.error(f"[GOOGLE] Audience mismatch: {aud}")
            return jsonify({"error": "Invalid Google token audience"}), 400

        email     = info.get("email", "").lower()
        name      = info.get("name", "") or info.get("given_name", "")
        picture   = info.get("picture", "")
        google_id = info.get("sub", "")

        if not email:
            return jsonify({"error": "No email from Google"}), 400
        
        # Email must be verified by Google
        if info.get("email_verified") == "false":
            return jsonify({"error": "Google email not verified"}), 400

        u = User.query.filter_by(email=email).first()
        is_new = False
        if not u:
            is_new = True
            u = User(
                email=email,
                name=name,
                google_id=google_id,
                avatar_url=picture,
                plan="trial",
                plan_expires=datetime.utcnow() + timedelta(days=2),
                is_admin=(email in ADMIN_EMAILS),
            )
            db.session.add(u)
        else:
            u.google_id   = google_id
            u.avatar_url  = picture
            if not u.name and name:
                u.name = name

        u.login_count = (u.login_count or 0) + 1
        u.last_login  = datetime.utcnow()
        db.session.commit()
        
        if is_new:
            try: welcome_email(u)
            except Exception as e: log.warning(f"[GOOGLE WELCOME EMAIL] {e}")

        log.info(f"[GOOGLE LOGIN] {email} (new={is_new})")
        return jsonify({"token": make_token(u), "user": u.to_dict()})

    except Exception as e:
        log.error(f"[GOOGLE ERROR] {str(e)}", exc_info=True)
        return jsonify({"error": "Google login failed. Please try again or use email login."}), 500


@app.route("/api/auth/me")
@auth_required
def auth_me():
    return jsonify({"user": g.user.to_dict()})


@app.route("/api/auth/profile", methods=["PUT"])
@auth_required
def update_profile():
    data = request.json or {}
    g.user.name = data.get("name", g.user.name).strip()
    g.user.phone = data.get("phone", g.user.phone).strip()
    new_email = data.get("email", "").strip().lower()
    if new_email and new_email != g.user.email:
        existing = User.query.filter_by(email=new_email).first()
        if existing:
            return jsonify({"error": "Email already in use"}), 400
        g.user.email = new_email

    new_pwd = data.get("password", "").strip()
    if new_pwd:
        if len(new_pwd) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        g.user.password_hash = hash_password(new_pwd)

    db.session.commit()
    return jsonify({"user": g.user.to_dict()})


# ═══════ PAYMENT ROUTES (DIRECT LINKS) ═══════

@app.route("/api/payment/links")
def get_payment_links():
    return jsonify({
        "monthly":   RAZORPAY_MONTHLY_LINK,
        "quarterly": RAZORPAY_QUARTERLY_LINK,
        "yearly":    RAZORPAY_YEARLY_LINK,
        "return_url": FRONTEND_URL,
    })



# ═══════ PAYMENT WEBHOOK ═══════

@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    """
    Razorpay webhook for payment_link.paid events.
    CRITICAL: This is how the system knows a user has paid.
    Configure in Razorpay Dashboard → Webhooks → Add URL → /api/payment/webhook
    Subscribe to: payment_link.paid
    """
    try:
        # Verify Razorpay signature if secret is configured
        if RAZORPAY_WEBHOOK_SECRET:
            import hmac, hashlib as hl
            sig = request.headers.get("X-Razorpay-Signature", "")
            body = request.get_data()
            expected = hmac.new(
                RAZORPAY_WEBHOOK_SECRET.encode(),
                body,
                hl.sha256
            ).hexdigest()
            if sig and sig != expected:
                log.error("[WEBHOOK] Signature mismatch - possible fake webhook")
                return jsonify({"error": "Invalid signature"}), 400

        data  = request.json or {}
        event = data.get("event", "")
        log.info(f"[WEBHOOK] Event received: {event}")

        if event == "payment_link.paid":
            payload      = data.get("payload", {})
            payment_link = payload.get("payment_link", {}).get("entity", 
                           payload.get("payment_link", {}))
            payment      = payload.get("payment", {}).get("entity",
                           payload.get("payment", {}))

            # Extract email — Razorpay stores it in notes or customer details
            notes  = payment_link.get("notes", {}) or {}
            email  = (notes.get("email") or 
                      payment_link.get("customer", {}).get("email") or
                      payment.get("email") or "").strip().lower()
            plan   = (notes.get("plan") or 
                      payment_link.get("description", "monthly").lower().split()[0] or
                      "monthly")
            amount = payment.get("amount", 0) / 100  # paise to rupees
            pay_id = payment.get("id", "")

            log.info(f"[WEBHOOK] Payment: email={email}, plan={plan}, amount=₹{amount}, id={pay_id}")

            if not email:
                log.error("[WEBHOOK] No email in payment - cannot update user")
                # Still return 200 so Razorpay doesn't retry infinitely
                return jsonify({"status": "ok", "warning": "no_email"})

            user = User.query.filter_by(email=email).first()
            if not user:
                log.error(f"[WEBHOOK] User not found for email: {email}")
                return jsonify({"status": "ok", "warning": "user_not_found"})

            # Map plan to days
            days_map = {"monthly": 30, "quarterly": 90, "yearly": 365}
            days = days_map.get(plan, 30)

            # If already pro, extend from current expiry instead of now
            if user.is_pro() and user.plan_expires and user.plan_expires > datetime.utcnow():
                user.plan_expires = user.plan_expires + timedelta(days=days)
            else:
                user.plan_expires = datetime.utcnow() + timedelta(days=days)
            
            user.plan = plan
            user.razorpay_payment_id = pay_id
            user.total_paid = (user.total_paid or 0) + amount

            # Record in payments table (prevent duplicate recording)
            existing_payment = Payment.query.filter_by(razorpay_payment_id=pay_id).first()
            if not existing_payment:
                p = Payment(
                    user_id=user.id,
                    razorpay_payment_id=pay_id,
                    amount=amount,
                    plan=plan,
                    status="success",
                )
                db.session.add(p)

            db.session.commit()
            log.info(f"[WEBHOOK] ✅ Upgraded {email} to {plan} until {user.plan_expires.date()}")

            # Send confirmation email
            try: subscription_email(user, plan, amount)
            except Exception as e: log.warning(f"[WEBHOOK EMAIL] {e}")

        return jsonify({"status": "ok"})

    except Exception as e:
        log.error(f"[WEBHOOK ERROR] {e}", exc_info=True)
        # Return 200 anyway so Razorpay doesn't keep retrying
        return jsonify({"status": "ok", "error": str(e)})


@app.route("/api/payment/verify", methods=["POST"])
@auth_required
def verify_payment():
    """
    Frontend polls this after returning from Razorpay to check if webhook 
    has processed and user is now Pro. Returns fresh user data.
    """
    # Refresh user from DB (not from token cache)
    fresh_user = User.query.get(g.user.id)
    return jsonify({
        "user": fresh_user.to_dict(),
        "isPro": fresh_user.is_pro(),
        "plan": fresh_user.plan,
        "planExpires": fresh_user.plan_expires.isoformat() if fresh_user.plan_expires else None,
    })


# ═══════ WATCHLIST ROUTES ═══════

@app.route("/api/watchlist")
@auth_required
def get_watchlist():
    items = WatchlistItem.query.filter_by(user_id=g.user.id).order_by(WatchlistItem.added_at.desc()).all()
    return jsonify([item.to_dict() for item in items])


@app.route("/api/watchlist", methods=["POST"])
@auth_required
def add_watchlist():
    data = request.json or {}
    sym = data.get("sym", "").upper()
    if not sym:
        return jsonify({"error": "Symbol required"}), 400

    existing = WatchlistItem.query.filter_by(user_id=g.user.id, symbol=sym).first()
    if existing:
        existing.cmp = data.get("cmp", existing.cmp)
        existing.mcap = data.get("mcap", existing.mcap)
        existing.implied_growth = data.get("ig")
        existing.intrinsic_value = data.get("iv", existing.intrinsic_value)
        existing.gap = data.get("gap", existing.gap)
        existing.exit_pe = data.get("inputs", {}).get("pe", existing.exit_pe)
        existing.discount_rate = data.get("inputs", {}).get("dr", existing.discount_rate)
        existing.forecast_years = data.get("inputs", {}).get("fy", existing.forecast_years)
        existing.expected_cagr = data.get("inputs", {}).get("ec", existing.expected_cagr)
        existing.updated_at = datetime.utcnow()
    else:
        item = WatchlistItem(
            user_id=g.user.id,
            symbol=sym,
            name=data.get("name", ""),
            sector=data.get("sec", ""),
            cmp=data.get("cmp", 0),
            mcap=data.get("mcap", 0),
            implied_growth=data.get("ig"),
            intrinsic_value=data.get("iv", 0),
            gap=data.get("gap", 0),
            exit_pe=data.get("inputs", {}).get("pe", 20),
            discount_rate=data.get("inputs", {}).get("dr", 15),
            forecast_years=data.get("inputs", {}).get("fy", 10),
            expected_cagr=data.get("inputs", {}).get("ec", 15),
        )
        db.session.add(item)

    db.session.commit()
    items = WatchlistItem.query.filter_by(user_id=g.user.id).order_by(WatchlistItem.added_at.desc()).all()
    return jsonify([item.to_dict() for item in items])


@app.route("/api/watchlist/<int:item_id>", methods=["DELETE"])
@auth_required
def delete_watchlist(item_id):
    item = WatchlistItem.query.filter_by(id=item_id, user_id=g.user.id).first()
    if not item:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(item)
    db.session.commit()
    items = WatchlistItem.query.filter_by(user_id=g.user.id).order_by(WatchlistItem.added_at.desc()).all()
    return jsonify([item.to_dict() for item in items])


# ═══════ ADMIN ROUTES ═══════

@app.route("/api/admin/stats")
@auth_required
@admin_required
def admin_stats():
    total = User.query.count()
    trial = User.query.filter_by(plan="trial").count()
    paid = User.query.filter(User.plan.in_(["monthly", "quarterly", "yearly"])).count()
    revenue = db.session.query(db.func.sum(User.total_paid)).scalar() or 0

    recent = User.query.order_by(User.created_at.desc()).limit(50).all()
    # Build payment history per user
    payments_raw = Payment.query.order_by(Payment.created_at.desc()).all()
    payment_map = {}
    for p in payments_raw:
        payment_map.setdefault(p.user_id, []).append({
            "id": p.razorpay_payment_id,
            "amount": p.amount,
            "plan": p.plan,
            "date": p.created_at.isoformat() if p.created_at else None,
        })

    users_data = []
    for u in recent:
        d = u.to_dict(include_private=True)
        d["payments"] = payment_map.get(u.id, [])
        users_data.append(d)

    return jsonify({
        "total": total,
        "trial": trial,
        "paid": paid,
        "revenue": round(revenue, 2),
        "recent": users_data,
        "users": users_data,
    })




@app.route("/api/admin/users")
@auth_required
@admin_required
def admin_users():
    """Return paginated user list with subscription and payment info."""
    page  = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 100, type=int)
    plan_filter = request.args.get("plan", "")

    q = User.query
    if plan_filter:
        q = q.filter_by(plan=plan_filter)
    total = q.count()
    users = q.order_by(User.created_at.desc()).offset((page-1)*limit).limit(limit).all()

    payments_raw = Payment.query.filter(Payment.user_id.in_([u.id for u in users])).all()
    payment_map = {}
    for p in payments_raw:
        payment_map.setdefault(p.user_id, []).append({
            "id": p.razorpay_payment_id, "amount": p.amount,
            "plan": p.plan, "date": p.created_at.isoformat() if p.created_at else None,
        })

    data = []
    for u in users:
        d = u.to_dict(include_private=True)
        d["payments"] = payment_map.get(u.id, [])
        data.append(d)

    return jsonify({"total": total, "page": page, "users": data})


@app.route("/api/admin/toggle-pro", methods=["POST"])
@auth_required
@admin_required
def admin_toggle_pro():
    """Manually grant or revoke Pro for a user."""
    data = request.json or {}
    uid     = data.get("user_id")
    is_pro  = data.get("is_pro", True)
    plan    = data.get("plan", "monthly")
    u = User.query.get(uid)
    if not u:
        return jsonify({"error": "User not found"}), 404
    if is_pro:
        u.plan = plan
        u.plan_expires = datetime.utcnow() + timedelta(days=30)
    else:
        u.plan = "free"
        u.plan_expires = None
    db.session.commit()
    log.info(f"[ADMIN] toggle-pro user={u.email} is_pro={is_pro}")
    return jsonify({"ok": True, "user": u.to_dict()})


@app.route("/api/admin/make-admin", methods=["POST"])
@auth_required
@admin_required
def admin_make_admin():
    """Grant admin rights to a user by email."""
    email = (request.json or {}).get("email", "").strip().lower()
    u = User.query.filter_by(email=email).first()
    if not u:
        return jsonify({"error": "User not found"}), 404
    u.is_admin = True
    db.session.commit()
    log.info(f"[ADMIN] made admin: {email}")
    return jsonify({"ok": True})


@app.route("/api/admin/payments")
@auth_required
@admin_required
def admin_payments():
    """Full payment history with analytics."""
    payments = Payment.query.order_by(Payment.created_at.desc()).limit(200).all()
    # Revenue by plan
    monthly_rev   = sum(p.amount for p in payments if p.plan == "monthly")
    quarterly_rev = sum(p.amount for p in payments if p.plan == "quarterly")
    yearly_rev    = sum(p.amount for p in payments if p.plan == "yearly")
    return jsonify({
        "payments": [
            {
                "id": p.razorpay_payment_id,
                "user_id": p.user_id,
                "amount": p.amount,
                "plan": p.plan,
                "status": p.status,
                "date": p.created_at.isoformat() if p.created_at else None,
            } for p in payments
        ],
        "analytics": {
            "total_revenue": round(monthly_rev + quarterly_rev + yearly_rev, 2),
            "by_plan": {
                "monthly": {"count": sum(1 for p in payments if p.plan=="monthly"), "revenue": round(monthly_rev,2)},
                "quarterly": {"count": sum(1 for p in payments if p.plan=="quarterly"), "revenue": round(quarterly_rev,2)},
                "yearly": {"count": sum(1 for p in payments if p.plan=="yearly"), "revenue": round(yearly_rev,2)},
            }
        }
    })

# ═══════ SENTIMENT ANALYSIS (GROK) ═══════

@app.route("/api/sentiment/<symbol>")
@auth_required
def get_sentiment(symbol):
    """Analyze stock sentiment using Grok API"""
    
    if not GROK_API_KEY:
        log.warning("[SENTIMENT] GROK_API_KEY not configured - returning mock data")
        # Return mock sentiment data for demo purposes
        return jsonify({
            "overall": "Neutral",
            "overallScore": 6,
            "summary": f"Sentiment analysis for {symbol.upper()} is currently in demo mode. Configure GROK_API_KEY environment variable to enable live AI-powered analysis.",
            "categories": [
                {
                    "name": "Social Media",
                    "sentiment": "Neutral",
                    "score": 6,
                    "points": ["Demo mode active", "Configure Grok API key for live analysis"]
                },
                {
                    "name": "News Sentiment",
                    "sentiment": "Neutral",
                    "score": 6,
                    "points": ["Demo mode active", "Real-time news analysis available with API key"]
                },
                {
                    "name": "Analyst Sentiment",
                    "sentiment": "Neutral",
                    "score": 6,
                    "points": ["Demo mode active", "Analyst views available with API key"]
                }
            ],
            "recentTriggers": ["Demo mode - Add GROK_API_KEY to enable live analysis"],
            "recommendation": "This is demo sentiment data. Get your Grok API key from https://x.ai/api and add it to your environment variables as GROK_API_KEY to enable real AI-powered sentiment analysis."
        })
    
    sym = symbol.upper()
    
    # Build prompt for Grok
    current_date = datetime.now().strftime("%B %d, %Y")
    
    prompt = f"""TODAY IS {current_date}. You are a financial analyst with REAL-TIME web search access.

🔍 MANDATORY WEB SEARCH INSTRUCTIONS:

1. SEARCH Google for: "{sym} Q3 FY26 results" OR "{sym} Q3 FY2026 results" OR "{sym} quarterly results February 2026"
2. SEARCH Google for: "{sym} latest news" (restrict to past 14 days)
3. SEARCH Twitter/X for: "{sym}" OR "POLICYBZR" (if {sym} is ticker, search company name too)
4. SEARCH Moneycontrol.com specifically: "site:moneycontrol.com {sym}"
5. SEARCH Economic Times: "site:economictimes.indiatimes.com {sym}"
6. SEARCH Reddit: "site:reddit.com/r/IndianStreetBets {sym}" AND "site:reddit.com/r/IndiaInvestments {sym}"
7. SEARCH for company announcements: "{sym} NSE announcement" OR "{sym} BSE filing"

⚠️ CRITICAL RULES:
- You MUST perform actual Google searches, not rely on training data
- Search with multiple query variations if first search yields no results
- For Indian stocks, also search by company full name (e.g., "PB Fintech" for POLICYBZR)
- Check BOTH NSE and BSE websites for announcements
- Look for Q3 FY26, Q3 FY2026, Q3 2025-26 (all formats)
- Today is {current_date}, so "recent" means within last 14 days

📊 SPECIFIC THINGS TO SEARCH:

For {sym} (Indian stock):

**Earnings/Results** (HIGHEST PRIORITY):
- "{{sym}} Q3 results" + date range: Jan 15 - Feb 16, 2026
- "{{sym}} quarterly results February 2026"
- "{{sym}} earnings announcement"
- Check: Moneycontrol earnings section, NSE/BSE filings

**News** (past 14 days):
- Economic Times articles about {{sym}}
- Moneycontrol news on {{sym}}
- Business Standard coverage of {{sym}}
- Mint articles featuring {{sym}}

**Social Media** (past 7 days):
- Twitter/X: Search "{{sym}}" AND search company full name
- Reddit r/IndianStreetBets: latest posts about {{sym}}
- Reddit r/IndiaInvestments: discussions on {{sym}}

**Analyst Coverage** (past 30 days):
- "{{sym}} broker report" + February 2026
- "{{sym}} price target" + upgrade/downgrade
- "{{sym}} analyst recommendation" + recent

**Company Actions**:
- NSE/BSE announcements for {{sym}}
- Company press releases
- Investor presentations

🎯 OUTPUT REQUIREMENTS:

1. If you find Q3 results: Include exact date, key numbers (revenue, profit, growth %), and source
2. If you find news: Include headline, date, and source URL/publication
3. If you find social discussions: Include platform, date, and sentiment
4. For each data point: MUST include date and source
5. If truly no data found after searching: Be explicit: "Searched X sources, found no results"

⛔ DO NOT SAY "Limited recent data available" unless you:
- Explicitly searched Google for the company
- Checked Economic Times, Moneycontrol, Business Standard
- Searched Twitter/X with both ticker and company name
- Checked Reddit forums
- Verified no NSE/BSE announcements

Format response as JSON:
{{{{
  "overall": "Positive/Neutral/Negative",
  "overallScore": 7,
  "summary": "Include specific dates and events found in search",
  "categories": [
    {{{{
      "name": "Category Name",
      "sentiment": "Positive/Neutral/Negative",
      "score": 8,
      "points": [
        "Specific point WITH date and source (e.g., 'Feb 2, 2026: Q3 results...')",
        "Another point with date and source"
      ]
    }}}}
  ],
  "recentTriggers": ["Event with specific date"],
  "recommendation": "Based on search findings",
  "searchesPerformed": "List what you actually searched for",
  "dataFreshness": "Mention date range of data and sources checked"
}}}}

🔍 SEARCH NOW for {sym} and provide analysis based on ACTUAL search results, not assumptions."""

    try:
        log.info(f"[SENTIMENT] Starting analysis for {sym}")
        log.info(f"[SENTIMENT] API Key present: {bool(GROK_API_KEY)}")
        log.info(f"[SENTIMENT] API Key starts with: {GROK_API_KEY[:10] if GROK_API_KEY else 'NONE'}...")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROK_API_KEY}"
        }
        
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a financial analyst expert at analyzing market sentiment. Provide factual, data-driven analysis."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "model": "grok-4-1-fast-reasoning",
            "stream": False,
            "temperature": 0.3
        }
        
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code != 200:
            log.error(f"[GROK ERROR] Status: {response.status_code}")
            log.error(f"[GROK ERROR] Response: {response.text}")
            
            # Return user-friendly error based on status code
            if response.status_code == 401:
                return jsonify({
                    "error": "Invalid Grok API key. Please check your GROK_API_KEY environment variable.",
                    "details": "Authentication failed"
                }), 401
            elif response.status_code == 429:
                return jsonify({
                    "error": "Rate limit exceeded. Please try again in a few moments.",
                    "details": "Too many requests"
                }), 429
            elif response.status_code == 403:
                return jsonify({
                    "error": "Access forbidden. Check if your Grok API key has sufficient credits.",
                    "details": "Insufficient permissions or credits"
                }), 403
            else:
                return jsonify({
                    "error": f"Grok API error (Status: {response.status_code})",
                    "details": response.text[:200] if response.text else "Unknown error"
                }), 500
        
        result = response.json()
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Try to parse JSON from content
        import re
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            sentiment_data = json.loads(json_match.group())
            return jsonify(sentiment_data)
        else:
            # Return raw content if JSON parsing fails
            return jsonify({
                "overall": "Neutral",
                "overallScore": 5,
                "summary": content[:500],
                "raw": content
            })
    
    except requests.exceptions.Timeout:
        log.error(f"[SENTIMENT TIMEOUT] {sym}")
        return jsonify({"error": "Request timeout - Grok API is taking too long. Please try again."}), 504
    except requests.exceptions.RequestException as e:
        log.error(f"[SENTIMENT REQUEST ERROR] {sym}: {e}")
        return jsonify({"error": "Failed to connect to Grok API. Check your API key and internet connection."}), 500
    except Exception as e:
        log.error(f"[SENTIMENT ERROR] {sym}: {e}")
        return jsonify({"error": f"Sentiment analysis failed: {str(e)}"}), 500


# ═══════ PROP RESEARCH ROUTES ═══════

@app.route("/api/prop-research")
def get_prop_research():
    """Get all published prop research"""
    research = PropResearch.query.filter_by(is_active=True).order_by(PropResearch.published_at.desc()).all()
    return jsonify([r.to_dict() for r in research])


@app.route("/api/prop-research/<int:research_id>")
def get_research_detail(research_id):
    """Get detailed research by ID and increment views"""
    research = PropResearch.query.get(research_id)
    if not research or not research.is_active:
        return jsonify({"error": "Not found"}), 404
    
    research.views = (research.views or 0) + 1
    db.session.commit()
    
    return jsonify(research.to_dict())


@app.route("/api/prop-research", methods=["POST"])
@auth_required
@admin_required
def create_prop_research():
    """Admin: Create new prop research"""
    data = request.json or {}
    
    # Accept both snake_case (admin form) and camelCase
    def gd(snake, camel, default=""):
        return data.get(snake, data.get(camel, default))

    research = PropResearch(
        title=       gd("title",        "title"),
        symbol=      gd("symbol",       "symbol").upper(),
        sector=      gd("sector",       "sector"),
        thesis=      gd("thesis",       "thesis"),
        target_cagr= gd("target_cagr",  "targetCagr",  25),
        time_horizon=gd("time_horizon", "timeHorizon", "12"),
        entry_price= gd("entry_price",  "entryPrice",  0),
        target_price=gd("target_price", "targetPrice", 0),
        risks=       gd("risks",        "risks"),
        catalysts=   gd("catalysts",    "catalysts"),
        content=     gd("content",      "content"),
        is_active=   data.get("isActive", True),
    )
    
    db.session.add(research)
    db.session.commit()
    
    log.info(f"[PROP RESEARCH] Created: {research.title}")
    return jsonify(research.to_dict())


@app.route("/api/prop-research/<int:research_id>", methods=["PUT"])
@auth_required
@admin_required
def update_prop_research(research_id):
    """Admin: Update prop research"""
    research = PropResearch.query.get(research_id)
    if not research:
        return jsonify({"error": "Not found"}), 404
    
    data = request.json or {}
    # Accept both snake_case (from form) and camelCase (legacy)
    def get(snake, camel, default):
        return data.get(snake, data.get(camel, default))
    research.title       = get("title",        "title",       research.title)
    research.symbol      = get("symbol",        "symbol",      research.symbol or "").upper()
    research.sector      = get("sector",        "sector",      research.sector)
    research.thesis      = get("thesis",        "thesis",      research.thesis)
    research.target_cagr = get("target_cagr",   "targetCagr",  research.target_cagr)
    research.time_horizon= get("time_horizon",  "timeHorizon", research.time_horizon)
    research.entry_price = get("entry_price",   "entryPrice",  research.entry_price)
    research.target_price= get("target_price",  "targetPrice", research.target_price)
    research.risks       = get("risks",         "risks",       research.risks)
    research.catalysts   = get("catalysts",     "catalysts",   research.catalysts)
    research.content     = get("content",       "content",     research.content)
    research.is_active   = get("isActive",      "isActive",    research.is_active)
    
    db.session.commit()
    return jsonify(research.to_dict())


@app.route("/api/prop-research/<int:research_id>", methods=["DELETE"])
@auth_required
@admin_required
def delete_prop_research(research_id):
    """Admin: Soft delete prop research"""
    research = PropResearch.query.get(research_id)
    if not research:
        return jsonify({"error": "Not found"}), 404
    
    research.is_active = False
    db.session.commit()
    return jsonify({"status": "deleted"})


# ═══════ YFINANCE HELPERS ═══════

def yf_quote(symbol):
    ticker = symbol if "." in symbol else symbol + ".NS"
    try:
        t = yf.Ticker(ticker)
        info = t.info
        if not info or not info.get("regularMarketPrice"):
            if not ticker.endswith(".BO"):
                ticker = symbol.replace(".NS", "") + ".BO"
                t = yf.Ticker(ticker)
                info = t.info
                if not info or not info.get("regularMarketPrice"):
                    return None

        cmp = info.get("regularMarketPrice") or info.get("currentPrice") or 0
        mcap = info.get("marketCap", 0)
        shares = (mcap / cmp) if cmp > 0 else 0
        mcap_cr = mcap / 1e7
        shares_cr = shares / 1e7

        return {
            "cmp": round(cmp, 2),
            "mcap_cr": round(mcap_cr, 2),
            "shares_cr": round(shares_cr, 2),
            "pe": round(info.get("trailingPE", 0) or 0, 2),
            "eps": round(info.get("trailingEps", 0) or 0, 2),
            "name": info.get("longName") or info.get("shortName") or symbol,
            "sector": info.get("sector") or "",
            "industry": info.get("industry") or "",
            "change": round((info.get("regularMarketChange", 0) or 0), 2),
            "changePct": round((info.get("regularMarketChangePercent", 0) or 0), 2),
            "yearHigh": info.get("fiftyTwoWeekHigh", 0),
            "yearLow": info.get("fiftyTwoWeekLow", 0),
            "bookValue": info.get("bookValue", 0),
            "dividendYield": round((info.get("dividendYield", 0) or 0) * 100, 2),
            "currency": info.get("currency", "INR"),
        }
    except Exception as e:
        log.error(f"[YF QUOTE ERROR] {ticker}: {e}")
        return None


def yf_financials(symbol):
    ticker = symbol if "." in symbol else symbol + ".NS"
    try:
        t = yf.Ticker(ticker)
        inc = t.financials
        if inc is None or inc.empty:
            if not ticker.endswith(".BO"):
                ticker2 = symbol.replace(".NS", "") + ".BO"
                t = yf.Ticker(ticker2)
                inc = t.financials
                if inc is None or inc.empty:
                    return None
        years = []
        for col in inc.columns:
            year = str(col.year) if hasattr(col, "year") else str(col)[:4]
            rev = pat = 0
            for key in ["Total Revenue", "Operating Revenue", "Revenue"]:
                if key in inc.index:
                    val = inc.at[key, col]
                    if val is not None and not (isinstance(val, float) and math.isnan(val)):
                        rev = float(val); break
            for key in ["Net Income", "Net Income Common Stockholders", "Net Income From Continuing Operations"]:
                if key in inc.index:
                    val = inc.at[key, col]
                    if val is not None and not (isinstance(val, float) and math.isnan(val)):
                        pat = float(val); break
            years.append({"year": year, "rev": round(rev / 1e7, 2), "pat": round(pat / 1e7, 2)})
        return years
    except Exception as e:
        log.error(f"[YF FIN ERROR] {ticker}: {e}")
        return None


def yf_search(query):
    results = []
    try:
        for suffix in [".NS", ".BO"]:
            try:
                t = yf.Ticker(query.upper() + suffix)
                info = t.info
                if info and info.get("regularMarketPrice"):
                    results.append({"sym": query.upper(), "name": info.get("longName") or query.upper(), "sec": info.get("sector") or "NSE"})
                    break
            except: continue
        try:
            sr = yf.Search(query, max_results=10)
            if hasattr(sr, 'quotes') and sr.quotes:
                for q in sr.quotes:
                    sym_raw = q.get("symbol", "")
                    if sym_raw.endswith(".NS") or sym_raw.endswith(".BO"):
                        sym_clean = sym_raw.replace(".NS", "").replace(".BO", "")
                        if not any(r["sym"] == sym_clean for r in results):
                            results.append({"sym": sym_clean, "name": q.get("longname") or sym_clean, "sec": q.get("sector") or "NSE"})
        except: pass
    except: pass
    return results[:15]


def calc_cagr(arr, field, n):
    if len(arr) < n + 1: return None
    a, b = arr[0].get(field, 0), arr[n].get(field, 0)
    if not b or b <= 0 or not a or a <= 0: return None
    return round((math.pow(a / b, 1 / n) - 1) * 100, 1)


# Stock API routes
@app.route("/api/search")
def search_stocks():
    q = request.args.get("q", "").strip()
    if not q or len(q) < 2: return jsonify([])
    ck = f"s:{q.lower()}"
    c = cached(ck, SEARCH_TTL)
    if c is not None: return jsonify(c)
    results = yf_search(q)
    set_cache(ck, results)
    return jsonify(results)


@app.route("/api/fullstock/<symbol>")
def fullstock(symbol):
    sym = symbol.upper().replace(".NS", "").replace(".BO", "")
    ck = f"f:{sym}"
    c = cached(ck, QUOTE_TTL)
    if c is not None: return jsonify(c)

    quote = yf_quote(sym)
    fck = f"fin:{sym}"
    years = cached(fck, FIN_TTL)
    if years is None:
        years = yf_financials(sym)
        if years: set_cache(fck, years)
    if not years: years = []

    cmp = quote["cmp"] if quote else 0
    mcap_cr = quote["mcap_cr"] if quote else 0
    pe = quote["pe"] if quote else 0

    result = {
        "sym": sym, "name": quote["name"] if quote else sym,
        "sec": quote["sector"] if quote else "Unknown",
        "industry": quote["industry"] if quote else "",
        "cmp": cmp, "shr": quote["shares_cr"] if quote else 0,
        "mcapCr": mcap_cr, "pe": pe, "eps": quote["eps"] if quote else 0,
        "pat": years[0]["pat"] if years else 0,
        "rev": years[0]["rev"] if years else 0,
        "r3": calc_cagr(years, "rev", 3), "r5": calc_cagr(years, "rev", 5),
        "p3": calc_cagr(years, "pat", 3), "p5": calc_cagr(years, "pat", 5),
        "dayChange": quote["change"] if quote else 0,
        "dayChangePct": quote["changePct"] if quote else 0,
        "yearHigh": quote["yearHigh"] if quote else 0,
        "yearLow": quote["yearLow"] if quote else 0,
        "bookValue": quote["bookValue"] if quote else 0,
        "dividendYield": quote["dividendYield"] if quote else 0,
        "_source": {"quote": "yfinance" if quote else "none", "financials": "yfinance" if years else "none", "years": len(years)},
    }
    # Track if logged in user
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            data = pyjwt.decode(auth[7:], app.config["SECRET_KEY"], algorithms=["HS256"])
            u = User.query.get(data["uid"])
            if u:
                u.stocks_analyzed = (u.stocks_analyzed or 0) + 1
                db.session.commit()
        except: pass

    set_cache(ck, result)
    return jsonify(result)


@app.route("/api/batch-quotes", methods=["POST"])
def batch_quotes():
    symbols = (request.json or {}).get("symbols", [])
    if not symbols: return jsonify([])
    results = []
    for sym in symbols[:20]:
        clean = sym.upper().replace(".NS", "").replace(".BO", "")
        q = yf_quote(clean)
        if q and q["cmp"] > 0:
            results.append({"sym": clean, "name": q["name"], "cmp": q["cmp"], "pe": q["pe"], "mcapCr": q["mcap_cr"]})
    return jsonify(results)


# ═══════ HEALTH & TEST ═══════

@app.route("/")
def health():
    return jsonify({
        "status": "ok", "service": "DIY Investing API v7",
        "source": "yfinance (INR native)",
        "features": ["auth", "google_oauth", "razorpay_links", "watchlist", "sentiment", "prop_research", "admin"],
        "db": "connected" if db.engine else "error",
    })


@app.route("/api/test")
def test_api():
    result = {"status": "ok", "tests": {}}
    try:
        q = yf_quote("TCS")
        result["tests"]["quote"] = {"working": bool(q and q["cmp"] > 0), "tcs_cmp": q["cmp"] if q else 0}
    except Exception as e:
        result["tests"]["quote"] = {"working": False, "error": str(e)}
    try:
        years = yf_financials("TCS")
        result["tests"]["financials"] = {"working": bool(years), "years": len(years) if years else 0}
    except Exception as e:
        result["tests"]["financials"] = {"working": False, "error": str(e)}
    try:
        count = User.query.count()
        result["tests"]["database"] = {"working": True, "users": count}
    except Exception as e:
        result["tests"]["database"] = {"working": False, "error": str(e)}
    return jsonify(result)


# ═══════ DB INIT & START ═══════

with app.app_context():
    db.create_all()
    log.info("Database tables created/verified")


if __name__ == "__main__":
    log.info(f"\n{'='*50}")
    log.info(f"  DIY Investing API v7")
    log.info(f"  Port: {PORT}")
    log.info(f"  DB: {app.config['SQLALCHEMY_DATABASE_URI'][:40]}...")
    log.info(f"  Google OAuth: {'YES' if GOOGLE_CLIENT_ID else 'NO'}")
    log.info(f"  Razorpay: {'YES' if RAZORPAY_KEY_ID else 'NO'}")
    log.info(f"  Grok API: {'YES' if GROK_API_KEY else 'NO'}")
    log.info(f"  Admin emails: {ADMIN_EMAILS}")
    log.info(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
