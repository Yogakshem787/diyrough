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

import os, time, math, logging, hashlib, secrets, json, re
import hmac as hmac_mod
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

# ═══════ RATE LIMITER ═══════
# Simple in-memory rate limiter (no extra dependency needed)
_rate_limits = {}  # key -> list of timestamps

def rate_limit_check(key, max_requests, window_seconds):
    """Return True if request is allowed, False if rate limited."""
    now = time.time()
    if key not in _rate_limits:
        _rate_limits[key] = []
    # Remove expired entries
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window_seconds]
    if len(_rate_limits[key]) >= max_requests:
        return False
    _rate_limits[key].append(now)
    return True

def get_client_ip():
    """Get real client IP, considering proxies."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

# ═══════ CONFIG ═══════
app = Flask(__name__)
# Allowed origins — add every domain that hosts your frontend
ALLOWED_ORIGINS = [
    "https://diyinvesting.in",
    "https://www.diyinvesting.in",
    "http://localhost:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5500",   # VS Code Live Server
]
# Also pull from env var so you can add more without redeploying
_extra = os.environ.get("EXTRA_ORIGINS", "")
if _extra:
    ALLOWED_ORIGINS += [o.strip() for o in _extra.split(",") if o.strip()]

CORS(app,
     resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Type"],
     supports_credentials=True,
     max_age=3600)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///diy.db")
# Fix Render's postgres:// vs postgresql://
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres://", "postgresql+psycopg://", 1)
elif app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Fix stale SSL connections after Render restart (SSL error: decryption failed)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 280,      # recycle connections every ~5 min (before Render's timeout)
    "pool_pre_ping": True,    # test connection before using it
    "pool_size": 5,
    "max_overflow": 10,
    "connect_args": {"connect_timeout": 10},
}

db = SQLAlchemy(app)

@app.after_request
def add_cors_headers(response):
    """Safety-net CORS headers — covers edge cases flask-cors misses."""
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Vary"]                             = "Origin"
    # Fix Google Sign-In COOP error: allow popup to postMessage back
    response.headers["Cross-Origin-Opener-Policy"]    = "same-origin-allow-popups"
    response.headers["Cross-Origin-Embedder-Policy"]  = "unsafe-none"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    """Handle all preflight OPTIONS requests."""
    response = app.make_default_options_response()
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Max-Age"]           = "3600"
    return response


@app.before_request
def csrf_origin_check():
    """Block state-changing requests from unknown origins (CSRF protection)."""
    if request.method in ("POST", "PUT", "DELETE"):
        origin = request.headers.get("Origin", "")
        # Allow requests with no Origin header (server-to-server, e.g. webhooks)
        if origin and origin not in ALLOWED_ORIGINS:
            # Exception: Razorpay webhooks come from Razorpay servers (no Origin)
            if "/api/payment/webhook" not in request.path:
                log.warning(f"[CSRF] Blocked request from origin: {origin} to {request.path}")
                return jsonify({"error": "Origin not allowed"}), 403

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


# ═══════ EMAIL HELPERS ═══════

def send_email(to_email, subject, html_body):
    """Send email via SMTP. Fails silently if SMTP not configured."""
    if not SMTP_USER or not SMTP_PASS:
        log.warning("[EMAIL] SMTP not configured — skipping email")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        log.info(f"[EMAIL] Sent to {to_email}: {subject}")
        return True
    except Exception as e:
        log.error(f"[EMAIL ERROR] {to_email}: {e}")
        return False


def welcome_email(user):
    """Send welcome email to new users."""
    send_email(
        user.email,
        "Welcome to DIY Investing! 🎉",
        f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <div style="background:linear-gradient(135deg,#0c1220,#1e293b);border-radius:12px;padding:28px;text-align:center;margin-bottom:20px">
                <div style="background:linear-gradient(135deg,#f59e0b,#ea580c);display:inline-block;width:48px;height:48px;border-radius:12px;line-height:48px;font-weight:900;color:#0c1220;font-size:16px;margin-bottom:12px">DI</div>
                <h1 style="color:#f1f5f9;font-size:22px;margin:0 0 4px">Welcome, {user.name or 'Investor'}!</h1>
                <p style="color:#94a3b8;font-size:13px;margin:0">Your 2-day free trial is now active</p>
            </div>
            <h2 style="font-size:16px;color:#0f172a;margin-bottom:12px">Here's what you can do:</h2>
            <ul style="color:#334155;font-size:13px;line-height:2">
                <li>🔄 <b>Reverse DCF</b> — Find implied growth for any Indian stock</li>
                <li>📊 <b>Curated Screens</b> — Bluechip, Midcap, Smallcap screens</li>
                <li>🤖 <b>AI Sentiment</b> — Real-time sentiment analysis</li>
                <li>💼 <b>Portfolio Tracker</b> — Import holdings & track DCF</li>
                <li>📋 <b>Watchlist</b> — Save & monitor your picks</li>
            </ul>
            <div style="text-align:center;margin:24px 0">
                <a href="{FRONTEND_URL}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;font-weight:700;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px">Start Analyzing Stocks →</a>
            </div>
            <p style="color:#94a3b8;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #e5e7eb;padding-top:16px">
                DIY Investing · Not financial advice · Always DYOR<br/>
                <a href="{FRONTEND_URL}" style="color:#f59e0b">{FRONTEND_URL}</a>
            </p>
        </div>
        """
    )


def subscription_email(user, plan, amount):
    """Send payment confirmation email."""
    plan_labels = {"monthly": "Monthly", "quarterly": "Quarterly (3 months)", "yearly": "Annual"}
    plan_label = plan_labels.get(plan, plan.title())
    expires_str = user.plan_expires.strftime("%d %B %Y") if user.plan_expires else "N/A"
    send_email(
        user.email,
        f"Payment Confirmed — {plan_label} Plan ✅",
        f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <div style="background:linear-gradient(135deg,#059669,#047857);border-radius:12px;padding:28px;text-align:center;margin-bottom:20px">
                <div style="font-size:40px;margin-bottom:8px">✅</div>
                <h1 style="color:#fff;font-size:22px;margin:0 0 4px">Payment Successful!</h1>
                <p style="color:#d1fae5;font-size:13px;margin:0">Thank you, {user.name or 'Investor'}!</p>
            </div>
            <div style="background:#f8fafc;border-radius:10px;padding:20px;margin-bottom:16px">
                <table style="width:100%;font-size:13px;color:#334155">
                    <tr><td style="padding:6px 0;color:#64748b">Plan</td><td style="padding:6px 0;text-align:right;font-weight:700">{plan_label}</td></tr>
                    <tr><td style="padding:6px 0;color:#64748b">Amount</td><td style="padding:6px 0;text-align:right;font-weight:700">₹{amount:.0f}</td></tr>
                    <tr><td style="padding:6px 0;color:#64748b">Valid Until</td><td style="padding:6px 0;text-align:right;font-weight:700">{expires_str}</td></tr>
                </table>
            </div>
            <p style="font-size:13px;color:#334155;line-height:1.6">
                All Pro features are now unlocked. Enjoy curated screens, AI sentiment analysis, unlimited watchlist, portfolio tracking, and proprietary research.
            </p>
            <div style="text-align:center;margin:24px 0">
                <a href="{FRONTEND_URL}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;font-weight:700;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px">Go to Dashboard →</a>
            </div>
            <p style="color:#94a3b8;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #e5e7eb;padding-top:16px">
                DIY Investing · Secure payments via Razorpay<br/>
                Questions? Reply to this email.
            </p>
        </div>
        """
    )


def renewal_reminder_email(user):
    """Send reminder 3 days before subscription expires."""
    expires_str = user.plan_expires.strftime("%d %B %Y") if user.plan_expires else "N/A"
    days_left = user.days_left()
    send_email(
        user.email,
        f"Your Pro plan expires in {days_left} day{'s' if days_left != 1 else ''} ⏰",
        f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <div style="background:linear-gradient(135deg,#f59e0b,#ea580c);border-radius:12px;padding:28px;text-align:center;margin-bottom:20px">
                <div style="font-size:40px;margin-bottom:8px">⏰</div>
                <h1 style="color:#fff;font-size:22px;margin:0 0 4px">Subscription Expiring Soon</h1>
                <p style="color:#fef3c7;font-size:13px;margin:0">Your Pro access expires on {expires_str}</p>
            </div>
            <p style="font-size:13px;color:#334155;line-height:1.6">
                Hi {user.name or 'there'}, your DIY Investing Pro plan expires in <b>{days_left} day{'s' if days_left != 1 else ''}</b>.
                Renew now to keep uninterrupted access to all features.
            </p>
            <div style="text-align:center;margin:24px 0">
                <a href="{FRONTEND_URL}?tab=pricing" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;font-weight:700;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px">Renew Now →</a>
            </div>
        </div>
        """
    )


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


class Portfolio(db.Model):
    """User's actual stock holdings for portfolio tracking + DCF analysis."""
    __tablename__ = "portfolio"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    symbol = db.Column(db.String(30), nullable=False, index=True)
    name = db.Column(db.String(255), default="")
    sector = db.Column(db.String(100), default="")
    
    # Purchase details
    quantity = db.Column(db.Float, nullable=False)  # number of shares
    buy_price = db.Column(db.Float, nullable=False)  # price per share when bought
    buy_date = db.Column(db.Date, nullable=False)
    
    # Current data (refreshed when user opens portfolio)
    current_price = db.Column(db.Float, default=0)
    
    # DCF inputs saved with this holding
    exit_pe = db.Column(db.Float, default=20)
    discount_rate = db.Column(db.Float, default=15)
    forecast_years = db.Column(db.Float, default=10)
    
    # Metadata
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "symbol": self.symbol,
            "name": self.name,
            "sector": self.sector,
            "quantity": self.quantity,
            "buyPrice": self.buy_price,
            "buyDate": self.buy_date.isoformat() if self.buy_date else None,
            "currentPrice": self.current_price,
            "exitPe": self.exit_pe,
            "discountRate": self.discount_rate,
            "forecastYears": self.forecast_years,
            "addedAt": self.added_at.isoformat() if self.added_at else None,
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


class StockCache(db.Model):
    """Persistent stock data cache that survives restarts."""
    __tablename__ = "stock_cache"
    key = db.Column(db.String(200), primary_key=True)
    data = db.Column(db.Text, default="")  # JSON
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ArticleComment(db.Model):
    """Comments on prop research articles."""
    __tablename__ = "article_comments"
    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey("prop_research.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    parent_id = db.Column(db.Integer, nullable=True)  # for replies
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="comments")

    def to_dict(self):
        return {
            "id": self.id,
            "articleId": self.article_id,
            "parentId": self.parent_id,
            "text": self.text,
            "author": self.user.name or self.user.email.split("@")[0] if self.user else "Anonymous",
            "isAdmin": self.user.is_admin if self.user else False,
            "createdAt": self.created_at.isoformat(),
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
        "exp": datetime.utcnow() + timedelta(days=7),
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
        # First do auth check (same as auth_required)
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Login required"}), 401
        try:
            data = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user = User.query.get(data["uid"])
            if not g.user:
                return jsonify({"error": "User not found"}), 401
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
        # Then check admin
        if not g.user.is_admin:
            log.warning(f"[ADMIN] Non-admin tried {request.path}: {g.user.email}")
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ═══════ CACHE (Hybrid: in-memory + DB persistent) ═══════
cache = {}
SEARCH_TTL = 7200    # search results: 2 hours
QUOTE_TTL  = 1800    # live quotes: 30 min (increased from 15 min to reduce rate limits)
FIN_TTL    = 259200   # financials: 72 hours (revenue/PAT only changes quarterly)
ERROR_TTL  = 120     # cache errors for 2 min to avoid hammering on failures
STALE_TTL  = 7200    # stale fallback data: 2 hours

# ── yfinance global throttle (prevents rate limiting) ──
_yf_last_call = 0
YF_MIN_INTERVAL = 3.0  # minimum 3 seconds between yfinance calls

def get_dynamic_quote_ttl():
    """Longer TTL off-market-hours to reduce yfinance calls."""
    try:
        from datetime import timezone
        ist = timezone(timedelta(hours=5, minutes=30))
        now = datetime.now(ist)
        # Weekend
        if now.weekday() >= 5:
            return 14400  # 4 hours
        # Market hours (9:15 AM - 3:30 PM IST)
        if 9 <= now.hour <= 15:
            return 1800   # 30 min during market
        return 7200  # 2 hours off-market
    except:
        return QUOTE_TTL

def cached(key, ttl):
    """Check in-memory cache first, then DB cache."""
    # Memory cache (fastest)
    if key in cache:
        val, exp = cache[key]
        if time.time() < exp:
            return val
        del cache[key]
    # DB cache (survives restarts)
    try:
        entry = StockCache.query.get(key)
        if entry and entry.expires_at > datetime.utcnow():
            val = json.loads(entry.data)
            # Promote to memory cache
            cache[key] = (val, entry.expires_at.timestamp())
            return val
        # Clean up expired entry
        if entry:
            db.session.delete(entry)
            db.session.commit()
    except Exception as e:
        log.debug(f"[CACHE DB] Read error for {key}: {e}")
    return None

def set_cache(key, val, ttl=None):
    """Write to both memory and DB cache."""
    effective_ttl = ttl or get_dynamic_quote_ttl()
    expires = time.time() + effective_ttl
    cache[key] = (val, expires)
    # Also persist to DB for crash recovery
    try:
        entry = StockCache.query.get(key)
        data_json = json.dumps(val)
        expires_dt = datetime.utcnow() + timedelta(seconds=effective_ttl)
        if entry:
            entry.data = data_json
            entry.expires_at = expires_dt
        else:
            entry = StockCache(key=key, data=data_json, expires_at=expires_dt)
            db.session.add(entry)
        db.session.commit()
    except Exception as e:
        log.debug(f"[CACHE DB] Write error for {key}: {e}")
        try:
            db.session.rollback()
        except:
            pass


# ═══════ AUTH ROUTES ═══════

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    # Rate limit: 5 signups per IP per 10 minutes
    ip = get_client_ip()
    if not rate_limit_check(f"signup:{ip}", 5, 600):
        return jsonify({"error": "Too many signup attempts. Please try again in a few minutes."}), 429

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
    # Rate limit: 10 login attempts per IP per 5 minutes
    ip = get_client_ip()
    if not rate_limit_check(f"login:{ip}", 10, 300):
        return jsonify({"error": "Too many login attempts. Please wait a few minutes."}), 429

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
    # Rate limit: 10 Google auth attempts per IP per 5 minutes
    ip = get_client_ip()
    if not rate_limit_check(f"gauth:{ip}", 10, 300):
        return jsonify({"error": "Too many attempts. Please wait a few minutes."}), 429

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
                    timeout=15,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json'
                    }
                )
                if r.status_code == 200:
                    info = r.json()
                    break
                else:
                    # Try alternative endpoint
                    r2 = requests.get(
                        f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={credential}",
                        timeout=15,
                        headers={
                            'User-Agent': 'Mozilla/5.0',
                            'Accept': 'application/json'
                        }
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


# ═══════ PASSWORD RESET ═══════

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """Send a password reset link via email."""
    ip = get_client_ip()
    if not rate_limit_check(f"forgot:{ip}", 3, 600):
        return jsonify({"error": "Too many reset requests. Please wait 10 minutes."}), 429
    
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400
    
    u = User.query.filter_by(email=email).first()
    if u:
        # Generate time-limited reset token (1 hour expiry)
        reset_payload = {
            "uid": u.id,
            "purpose": "reset",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        reset_token = pyjwt.encode(reset_payload, app.config["SECRET_KEY"], algorithm="HS256")
        reset_url = f"{FRONTEND_URL}?reset_token={reset_token}"
        
        send_email(
            u.email,
            "Reset Your Password — DIY Investing",
            f"""
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
                <h2 style="color:#0f172a">Password Reset</h2>
                <p style="color:#334155;font-size:14px">Hi {u.name or 'there'},</p>
                <p style="color:#334155;font-size:14px">Click the button below to reset your password. This link expires in 1 hour.</p>
                <div style="text-align:center;margin:24px 0">
                    <a href="{reset_url}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff;font-weight:700;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px">Reset Password →</a>
                </div>
                <p style="color:#94a3b8;font-size:11px">If you didn't request this, you can safely ignore this email.</p>
            </div>
            """
        )
        log.info(f"[FORGOT] Reset email sent to {email}")
    
    # Always return success to prevent email enumeration
    return jsonify({"message": "If an account exists with that email, a reset link has been sent."})


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    """Reset password using a valid reset token."""
    data = request.json or {}
    token = data.get("token", "")
    new_password = data.get("password", "").strip()
    
    if not token or not new_password:
        return jsonify({"error": "Token and new password required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    try:
        payload = pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("purpose") != "reset":
            return jsonify({"error": "Invalid reset token"}), 400
        u = User.query.get(payload["uid"])
        if not u:
            return jsonify({"error": "User not found"}), 404
        u.password_hash = hash_password(new_password)
        db.session.commit()
        log.info(f"[RESET] Password reset for {u.email}")
        return jsonify({"message": "Password reset successfully. You can now login."})
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "Reset link has expired. Please request a new one."}), 400
    except Exception as e:
        log.error(f"[RESET ERROR] {e}")
        return jsonify({"error": "Invalid or expired reset token"}), 400


@app.route("/api/auth/profile", methods=["PUT"])
@auth_required
def update_profile():
    data = request.json or {}
    g.user.name = data.get("name", g.user.name).strip()
    g.user.phone = data.get("phone", g.user.phone).strip()

    # Email change requires current password verification (security)
    new_email = data.get("email", "").strip().lower()
    if new_email and new_email != g.user.email:
        current_pwd = data.get("currentPassword", "").strip()
        # Google-only users can change email without password
        if g.user.password_hash and not current_pwd:
            return jsonify({"error": "Current password required to change email"}), 400
        if g.user.password_hash and not verify_password(current_pwd, g.user.password_hash):
            return jsonify({"error": "Current password is incorrect"}), 400
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
    # Return a fresh token if email changed (old token has old email)
    result = {"user": g.user.to_dict()}
    if new_email and new_email != data.get("_original_email", ""):
        result["token"] = make_token(g.user)
    return jsonify(result)


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
            sig = request.headers.get("X-Razorpay-Signature", "")
            body = request.get_data()
            expected = hmac_mod.new(
                RAZORPAY_WEBHOOK_SECRET.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            # SECURITY: Reject if signature is missing OR doesn't match
            if not sig or sig != expected:
                log.error("[WEBHOOK] Signature mismatch or missing — possible fake webhook")
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
            customer = payment_link.get("customer", {}) or {}
            payment_notes = payment.get("notes", {}) or {}
            payment_customer = payment.get("customer", {}) or {}
            
            email  = (notes.get("email") or 
                      customer.get("email") or
                      customer.get("contact") or
                      payment.get("email") or 
                      payment_notes.get("email") or
                      payment_customer.get("email") or
                      "").strip().lower()
            plan   = (notes.get("plan") or 
                      payment_notes.get("plan") or
                      payment_link.get("description", "monthly").lower().split()[0] or
                      "monthly")
            amount = payment.get("amount", 0) / 100  # paise to rupees
            pay_id = payment.get("id", "")

            log.info(f"[WEBHOOK] Payment: email={email}, plan={plan}, amount=₹{amount}, id={pay_id}")
            # Log full payload for debugging payment issues
            log.info(f"[WEBHOOK] Notes: {json.dumps(notes)[:200]}")
            log.info(f"[WEBHOOK] Customer: {json.dumps(customer)[:200]}")

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



# ═══════ PORTFOLIO ROUTES ═══════

@app.route("/api/portfolio")
@auth_required
def get_portfolio():
    """Get user's portfolio holdings with live DCF analysis (optimized batch fetch)."""
    holdings = Portfolio.query.filter_by(user_id=g.user.id).order_by(Portfolio.buy_date.desc()).all()
    
    if not holdings:
        return jsonify([])
    
    # Batch fetch: collect unique symbols, fetch quotes once each
    unique_symbols = list(set(h.symbol.upper() for h in holdings))
    quotes = {}
    financials_map = {}
    
    for sym in unique_symbols:
        # Quote (uses cache, so won't hit yfinance if already cached)
        q = yf_quote(sym)
        if q:
            quotes[sym] = q
        # Financials
        fck = f"fin:{sym}"
        years = cached(fck, FIN_TTL)
        if years is None:
            years = yf_financials(sym)
            if years:
                set_cache(fck, years, FIN_TTL)
                set_cache(f"stale_fin:{sym}", years, 604800)
            else:
                # Serve stale financials rather than nothing
                years = cached(f"stale_fin:{sym}", 604800)
        financials_map[sym] = years or []
    
    result = []
    price_updated = False
    for h in holdings:
        sym = h.symbol.upper()
        quote = quotes.get(sym)
        years = financials_map.get(sym, [])
        
        # Update current price from quote
        if quote:
            h.current_price = quote.get('cmp', 0)
            price_updated = True
        
        pat = years[0].get('pat', 0) if years and len(years) > 0 else 0
        
        # Calculate DCF metrics
        invested = h.quantity * h.buy_price
        current_value = h.quantity * h.current_price
        pnl = current_value - invested
        pnl_pct = (pnl / invested * 100) if invested > 0 else 0
        
        # Implied growth calculation
        implied_growth = None
        if pat > 0 and h.current_price > 0:
            shares_cr = 0
            if quote and quote.get('shares_cr'):
                shares_cr = quote.get('shares_cr')
            elif quote and quote.get('mcap_cr'):
                shares_cr = quote['mcap_cr'] / h.current_price if h.current_price > 0 else 0
            
            if shares_cr > 0:
                mcap = h.current_price * shares_cr
                implied_growth = solveGrowth(
                    pat, mcap, h.discount_rate, h.forecast_years, h.exit_pe
                )
        
        result.append({
            **h.to_dict(),
            "invested": round(invested, 2),
            "currentValue": round(current_value, 2),
            "pnl": round(pnl, 2),
            "pnlPct": round(pnl_pct, 2),
            "pat": pat,
            "impliedGrowth": implied_growth,
        })
    
    # Single commit for all price updates (instead of per-holding)
    if price_updated:
        try:
            db.session.commit()
        except:
            db.session.rollback()
    
    return jsonify(result)


@app.route("/api/portfolio", methods=["POST"])
@auth_required
def add_portfolio_holding():
    """Add a new stock holding to portfolio."""
    data = request.json or {}
    
    symbol = data.get("symbol", "").upper().strip()
    quantity = data.get("quantity")
    buy_price = data.get("buyPrice")
    buy_date = data.get("buyDate")  # ISO format "2024-01-15"
    
    if not symbol or not quantity or not buy_price or not buy_date:
        return jsonify({"error": "Symbol, quantity, buyPrice, and buyDate required"}), 400
    
    try:
        quantity = float(quantity)
        buy_price = float(buy_price)
        buy_date_obj = datetime.fromisoformat(buy_date.split('T')[0])
    except:
        return jsonify({"error": "Invalid quantity, price, or date format"}), 400
    
    # Get stock name from quote or use symbol
    quote = yf_quote(symbol)
    name = quote.get('name', symbol) if quote else symbol
    sector = quote.get('sector', '') if quote else ''
    current_price = quote.get('cmp', buy_price) if quote else buy_price
    
    holding = Portfolio(
        user_id=g.user.id,
        symbol=symbol,
        name=name,
        sector=sector,
        quantity=quantity,
        buy_price=buy_price,
        buy_date=buy_date_obj,
        current_price=current_price,
        exit_pe=data.get("exitPe", 20),
        discount_rate=data.get("discountRate", 15),
        forecast_years=data.get("forecastYears", 10),
    )
    
    db.session.add(holding)
    db.session.commit()
    
    log.info(f"[PORTFOLIO] Added {symbol} for user {g.user.email}")
    
    # Return updated portfolio
    return get_portfolio()


@app.route("/api/portfolio/<int:holding_id>", methods=["PUT"])
@auth_required
def update_portfolio_holding(holding_id):
    """Update DCF parameters or quantity for a holding."""
    holding = Portfolio.query.filter_by(id=holding_id, user_id=g.user.id).first()
    if not holding:
        return jsonify({"error": "Holding not found"}), 404
    
    data = request.json or {}
    
    if "quantity" in data:
        holding.quantity = float(data["quantity"])
    if "exitPe" in data:
        holding.exit_pe = float(data["exitPe"])
    if "discountRate" in data:
        holding.discount_rate = float(data["discountRate"])
    if "forecastYears" in data:
        holding.forecast_years = float(data["forecastYears"])
    
    holding.updated_at = datetime.utcnow()
    db.session.commit()
    
    return get_portfolio()


@app.route("/api/portfolio/<int:holding_id>", methods=["DELETE"])
@auth_required
def delete_portfolio_holding(holding_id):
    """Remove a holding from portfolio."""
    holding = Portfolio.query.filter_by(id=holding_id, user_id=g.user.id).first()
    if not holding:
        return jsonify({"error": "Holding not found"}), 404
    
    db.session.delete(holding)
    db.session.commit()
    
    log.info(f"[PORTFOLIO] Deleted {holding.symbol} for user {g.user.email}")
    
    return get_portfolio()


@app.route("/api/portfolio/upload-csv", methods=["POST"])
@auth_required
def upload_portfolio_csv():
    """
    Parse CSV from any broker (Zerodha, Groww, Upstox, Angel One, etc.)
    and bulk import holdings into portfolio.
    
    Supports flexible formats - intelligently detects columns.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    
    file_ext = file.filename.lower().split(".")[-1]
    if file_ext not in ["csv", "xlsx", "xls"]:
        return jsonify({"error": "Please upload CSV or Excel file (.csv, .xlsx, .xls)"}), 400
    
    try:
        # Read CSV or Excel content
        import csv
        import io
        
        if file_ext in ["xlsx", "xls"]:
            # Parse Excel file
            try:
                import openpyxl
                from io import BytesIO
                
                # Read Excel
                wb = openpyxl.load_workbook(BytesIO(file.stream.read()), read_only=True)
                ws = wb.active
                
                # Convert to CSV-like structure
                rows = list(ws.iter_rows(values_only=True))
                if not rows:
                    return jsonify({"error": "Excel file is empty"}), 400
                
                # First row is headers
                headers_raw = rows[0]
                data_rows = rows[1:]
                
                # Create DictReader-like structure (normalize keys to lowercase)
                csv_reader = [{(str(k).strip().lower() if k else ""): (str(v).strip() if v else "") for k, v in zip(headers_raw, row)} for row in data_rows]
                fieldnames = headers_raw
                
            except ImportError:
                return jsonify({"error": "Excel support not installed. Please use CSV or contact support."}), 400
            except Exception as e:
                return jsonify({"error": f"Failed to parse Excel: {str(e)}"}), 400
        else:
            # Parse CSV file
            stream = io.StringIO(file.stream.read().decode("utf-8"), newline=None)
            csv_reader_obj = csv.DictReader(stream)
            fieldnames = csv_reader_obj.fieldnames
            # Normalize all row keys to lowercase for consistent column matching
            csv_reader = [{(k.strip().lower() if k else ""): (str(v).strip() if v else "") for k, v in row.items()} for row in csv_reader_obj]
        
        # Detect column mappings (different brokers use different headers)
        if file_ext in ["xlsx", "xls"]:
            headers = [str(h).strip().lower() if h else "" for h in fieldnames]
        else:
            headers = [h.strip().lower() for h in fieldnames] if fieldnames else []
        
        if not headers:
            return jsonify({"error": "CSV file is empty or has no headers"}), 400
        
        # Column mapping patterns (flexible matching)
        def find_column(patterns, headers):
            for pattern in patterns:
                for h in headers:
                    if re.search(pattern, h, re.IGNORECASE):
                        return h
            return None
        
        symbol_col = find_column([
            r'^symbol', r'^stock.*symbol', r'^trading.*symbol', r'^scrip', 
            r'^isin', r'^instrument'
        ], headers)
        
        qty_col = find_column([
            r'^qty', r'^quantity', r'^shares', r'^holding.*qty', r'^net.*qty'
        ], headers)
        
        avg_price_col = find_column([
            r'^avg.*price', r'^average.*price', r'^buy.*price', r'^purchase.*price',
            r'^price', r'^rate'
        ], headers)
        
        # Optional columns
        name_col = find_column([
            r'^name', r'^company', r'^stock.*name', r'^scrip.*name'
        ], headers)
        
        date_col = find_column([
            r'^date', r'^buy.*date', r'^purchase.*date', r'^trade.*date'
        ], headers)
        
        # Validation
        if not symbol_col:
            return jsonify({
                "error": "Could not find Symbol/Stock column. Headers found: " + ", ".join(headers[:5])
            }), 400
        
        if not qty_col:
            return jsonify({
                "error": "Could not find Quantity/Shares column. Headers found: " + ", ".join(headers[:5])
            }), 400
        
        if not avg_price_col:
            return jsonify({
                "error": "Could not find Price/Average Price column. Headers found: " + ", ".join(headers[:5])
            }), 400
        
        # Parse rows
        added = 0
        skipped = 0
        errors = []
        
        # Iterate through rows
        rows_to_process = csv_reader if file_ext in ["xlsx", "xls"] else csv_reader
        for i, row in enumerate(rows_to_process, start=2):  # start=2 because row 1 is headers
            try:
                # Extract data (all values are strings after normalization)
                symbol_raw = (row.get(symbol_col) or "").strip().upper()
                qty_raw = (row.get(qty_col) or "").strip()
                price_raw = (row.get(avg_price_col) or "").strip()
                
                # Clean symbol (remove .NS, .BO, exchange info)
                symbol = re.sub(r'\.(NS|BO|BSE|NSE)$', '', symbol_raw)
                symbol = re.sub(r'[^A-Z0-9&-]', '', symbol)  # Keep only alphanumeric, &, -
                
                if not symbol or symbol == "" or len(symbol) > 30:
                    skipped += 1
                    continue
                
                # Parse quantity
                try:
                    qty_clean = re.sub(r'[^\d.-]', '', qty_raw)
                    quantity = float(qty_clean)
                    if quantity <= 0:
                        skipped += 1
                        continue
                except:
                    skipped += 1
                    continue
                
                # Parse price
                try:
                    price_clean = re.sub(r'[^\d.-]', '', price_raw)
                    buy_price = float(price_clean)
                    if buy_price <= 0:
                        skipped += 1
                        continue
                except:
                    skipped += 1
                    continue
                
                # Parse date (optional)
                buy_date = None
                if date_col and row.get(date_col):
                    date_str = row.get(date_col, "").strip()
                    # Try multiple date formats
                    for fmt in ["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d", "%d-%b-%Y"]:
                        try:
                            buy_date = datetime.strptime(date_str, fmt).date()
                            break
                        except:
                            continue
                
                if not buy_date:
                    buy_date = datetime.utcnow().date()  # Default to today
                
                # Check if holding already exists (same symbol)
                existing = Portfolio.query.filter_by(
                    user_id=g.user.id, 
                    symbol=symbol
                ).first()
                
                if existing:
                    # Update quantity (aggregate multiple purchases)
                    total_qty = existing.quantity + quantity
                    # Weighted average price
                    total_cost = (existing.quantity * existing.buy_price) + (quantity * buy_price)
                    existing.quantity = total_qty
                    existing.buy_price = total_cost / total_qty
                    existing.updated_at = datetime.utcnow()
                    log.info(f"[CSV] Updated {symbol}: qty {total_qty}")
                else:
                    # Get stock name from yfinance (optional, don't fail if it doesn't work)
                    stock_name = row.get(name_col, symbol) if name_col else symbol
                    sector = ""
                    
                    # Try to fetch from yfinance (but don't block on rate limits)
                    try:
                        quote = yf_quote(symbol)
                        if quote:
                            stock_name = quote.get('name', stock_name)
                            sector = quote.get('sector', '')
                    except:
                        pass  # Continue even if yfinance fails
                    
                    # Create new holding
                    holding = Portfolio(
                        user_id=g.user.id,
                        symbol=symbol,
                        name=stock_name,
                        sector=sector,
                        quantity=quantity,
                        buy_price=buy_price,
                        buy_date=buy_date,
                        current_price=buy_price,  # Will be updated on next portfolio load
                        exit_pe=20,
                        discount_rate=15,
                        forecast_years=10,
                    )
                    db.session.add(holding)
                    log.info(f"[CSV] Added {symbol}: {quantity} @ ₹{buy_price}")
                
                added += 1
                
            except Exception as e:
                errors.append(f"Row {i}: {str(e)[:50]}")
                skipped += 1
                continue
        
        db.session.commit()
        
        log.info(f"[CSV UPLOAD] User {g.user.email}: {added} added, {skipped} skipped")
        
        return jsonify({
            "success": True,
            "added": added,
            "skipped": skipped,
            "errors": errors[:5] if errors else [],  # Return first 5 errors only
            "message": f"Successfully imported {added} holdings. {skipped} rows skipped.",
        })
        
    except Exception as e:
        log.error(f"[CSV UPLOAD ERROR] {e}", exc_info=True)
        return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400



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


@app.route("/api/admin/check-expiry", methods=["POST"])
@auth_required
@admin_required
def admin_check_expiry():
    """Check for expiring subscriptions and send reminders."""
    three_days = datetime.utcnow() + timedelta(days=3)
    expiring = User.query.filter(
        User.plan_expires <= three_days,
        User.plan_expires > datetime.utcnow(),
        User.plan.in_(["monthly", "quarterly", "yearly"]),
    ).all()
    
    sent = 0
    for u in expiring:
        try:
            renewal_reminder_email(u)
            sent += 1
        except Exception as e:
            log.error(f"[EXPIRY EMAIL] {u.email}: {e}")
    
    return jsonify({"checked": len(expiring), "reminders_sent": sent})


@app.route("/api/admin/cleanup-cache", methods=["POST"])
@auth_required
@admin_required
def admin_cleanup_cache():
    """Clean up expired DB cache entries."""
    try:
        expired = StockCache.query.filter(StockCache.expires_at < datetime.utcnow()).delete()
        db.session.commit()
        return jsonify({"deleted": expired})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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
    
    prompt = f"""You are a financial analyst. Today is {current_date}.

Analyze the current market sentiment for {sym} (Indian stock listed on NSE).

Based on your knowledge, provide a comprehensive sentiment analysis covering:

1. **Recent Quarterly Results**: What are the latest available quarterly results? (Revenue, PAT, growth YoY). If Q3 FY26 (Oct-Dec 2025) results are available, include them.

2. **News & Developments**: Any recent news, corporate actions, management changes, product launches, regulatory developments in the past 1-2 months.

3. **Social/Market Sentiment**: What is the general market buzz around this stock? Any notable analyst upgrades/downgrades? Retail investor sentiment.

4. **Key Catalysts & Risks**: What upcoming events could move the stock?

IMPORTANT:
- Be specific with numbers and dates where you have them
- If you don't have recent data on something, say "No recent data available" rather than making things up
- Indian financial year: Q3 FY26 = Oct-Dec 2025, Q4 FY26 = Jan-Mar 2026
- Also search for the company by its full name, not just ticker

Respond ONLY with valid JSON (no markdown, no backticks):
{{{{
  "overall": "Positive" or "Neutral" or "Negative",
  "overallScore": 1-10,
  "summary": "2-3 sentence summary with specific data points",
  "categories": [
    {{{{
      "name": "Quarterly Results",
      "sentiment": "Positive" or "Neutral" or "Negative",
      "score": 1-10,
      "points": ["Specific point with numbers and dates"]
    }}}},
    {{{{
      "name": "News & Developments",
      "sentiment": "Positive" or "Neutral" or "Negative",
      "score": 1-10,
      "points": ["Specific recent news items"]
    }}}},
    {{{{
      "name": "Market Sentiment",
      "sentiment": "Positive" or "Neutral" or "Negative",
      "score": 1-10,
      "points": ["Analyst views, retail sentiment"]
    }}}},
    {{{{
      "name": "Upcoming Catalysts",
      "sentiment": "Positive" or "Neutral" or "Negative",
      "score": 1-10,
      "points": ["Key upcoming events"]
    }}}}
  ],
  "recentTriggers": ["List of 2-3 recent events that moved or could move the stock"],
  "recommendation": "Overall assessment in 1-2 sentences"
}}}}"""

    try:
        log.info(f"[SENTIMENT] Starting analysis for {sym}")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROK_API_KEY}"
        }
        
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior Indian equity analyst. Provide factual, data-driven analysis. Always include specific numbers and dates. Respond ONLY with valid JSON, no markdown formatting."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "model": "grok-3-latest",
            "stream": False,
            "temperature": 0.2
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


# ═══════ ARTICLE COMMENTS ═══════

@app.route("/api/prop-research/<int:article_id>/comments")
def get_article_comments(article_id):
    """Get all comments for an article"""
    try:
        comments = ArticleComment.query.filter_by(article_id=article_id).order_by(ArticleComment.created_at.asc()).all()
        return jsonify([c.to_dict() for c in comments])
    except Exception as e:
        log.warning(f"[COMMENTS] Error fetching: {e}")
        # Table might not exist yet
        return jsonify([])


@app.route("/api/prop-research/<int:article_id>/comments", methods=["POST"])
@auth_required
def post_article_comment(article_id):
    """Post a comment or reply on an article"""
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text or len(text) > 2000:
        return jsonify({"error": "Comment must be 1-2000 characters"}), 400
    
    parent_id = data.get("parentId")
    
    try:
        comment = ArticleComment(
            article_id=article_id,
            user_id=request.user.id,
            parent_id=parent_id,
            text=text
        )
        db.session.add(comment)
        db.session.commit()
        
        # Return all comments for this article
        comments = ArticleComment.query.filter_by(article_id=article_id).order_by(ArticleComment.created_at.asc()).all()
        return jsonify([c.to_dict() for c in comments])
    except Exception as e:
        log.warning(f"[COMMENTS] Error posting: {e}")
        db.session.rollback()
        return jsonify({"error": "Could not post comment. Try again later."}), 500


# ═══════ MULTI-SOURCE STOCK DATA ENGINE ═══════
# Priority: nsetools (NSE direct, no rate limits) → NSE HTTP API → yfinance (last resort)
# yfinance is ONLY used for annual financials (revenue/PAT) which are cached 24h+

# ── Global NSE session (reuses cookies, avoids repeated handshakes) ──
_nse_session = None
_nse_cookies = None
_nse_cookie_time = 0
NSE_COOKIE_TTL = 300  # refresh cookies every 5 min

NSE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.nseindia.com/",
    "Connection": "keep-alive",
}


def _get_nse_session():
    """Get or refresh an HTTP session with valid NSE cookies."""
    global _nse_session, _nse_cookies, _nse_cookie_time
    now = time.time()
    if _nse_session and _nse_cookies and (now - _nse_cookie_time) < NSE_COOKIE_TTL:
        return _nse_session
    
    try:
        s = requests.Session()
        s.headers.update(NSE_HEADERS)
        # Hit NSE homepage to get cookies
        r = s.get("https://www.nseindia.com", timeout=10)
        if r.status_code == 200:
            _nse_session = s
            _nse_cookies = s.cookies
            _nse_cookie_time = now
            log.info("[NSE] Session cookies refreshed")
            return s
    except Exception as e:
        log.warning(f"[NSE] Cookie refresh failed: {e}")
    return None


def _nse_direct_quote(symbol):
    """
    Fetch quote directly from NSE India API.
    Returns same format as yf_quote for compatibility.
    No Yahoo dependency = no rate limits from Yahoo.
    """
    base = symbol.replace(".NS", "").replace(".BO", "").upper()
    s = _get_nse_session()
    if not s:
        log.debug(f"[NSE DIRECT] No session available for {base}")
        return None
    
    try:
        from urllib.parse import quote as url_quote
        encoded_sym = url_quote(base)
        url = f"https://www.nseindia.com/api/quote-equity?symbol={encoded_sym}"
        r = s.get(url, timeout=12)
        
        if r.status_code == 403:
            # Cookie expired mid-session, force refresh
            global _nse_cookie_time
            _nse_cookie_time = 0
            s = _get_nse_session()
            if s:
                r = s.get(url, timeout=12)
            else:
                return None
        
        if r.status_code != 200:
            log.warning(f"[NSE DIRECT] {base} HTTP {r.status_code}")
            return None
        
        data = r.json()
        if not data:
            return None
        
        pi = data.get("priceInfo", {}) or {}
        metadata = data.get("metadata", {}) or {}
        info = data.get("info", {}) or metadata
        industry_info = data.get("industryInfo", {}) or {}
        sec_info = data.get("securityInfo", {}) or {}
        
        cmp = pi.get("lastPrice") or pi.get("close") or pi.get("previousClose") or 0
        if not cmp or cmp <= 0:
            return None
        
        prev_close = pi.get("previousClose") or 0
        change = round(cmp - prev_close, 2) if prev_close else 0
        change_pct = round((change / prev_close) * 100, 2) if prev_close else 0
        
        # Shares outstanding from securityInfo
        issued_size = sec_info.get("issuedSize") or sec_info.get("issuedCap") or 0
        try:
            issued_size = int(issued_size) if issued_size else 0
        except:
            issued_size = 0
        mcap = cmp * issued_size if issued_size else 0
        
        wk = pi.get("weekHighLow", {}) or {}
        
        # PE from metadata (NSE stores it there)
        pe = metadata.get("pdSymbolPe") or metadata.get("pe") or info.get("pdSymbolPe") or 0
        try:
            pe = float(str(pe).replace(",", "")) if pe else 0
        except:
            pe = 0
        
        sector = (industry_info.get("macro") or 
                  industry_info.get("sector") or 
                  metadata.get("industry") or "")
        industry = (industry_info.get("basicIndustry") or 
                    industry_info.get("industry") or "")
        company_name = (info.get("companyName") or 
                        metadata.get("companyName") or 
                        metadata.get("symbol") or base)
        
        result = {
            "cmp":          round(cmp, 2),
            "mcap_cr":      round(mcap / 1e7, 2) if mcap else 0,
            "shares_cr":    round(issued_size / 1e7, 2) if issued_size else 0,
            "pe":           round(pe, 2),
            "eps":          round(cmp / pe, 2) if pe and pe > 0 else 0,
            "name":         company_name,
            "sector":       sector,
            "industry":     industry,
            "change":       change,
            "changePct":    change_pct,
            "yearHigh":     wk.get("max") or 0,
            "yearLow":      wk.get("min") or 0,
            "bookValue":    0,
            "dividendYield": 0,
            "currency":     "INR",
            "_source":      "nse_direct",
            "_ticker":      base + ".NS",
        }
        
        log.info(f"[NSE DIRECT] ✅ {base}: ₹{cmp} | mcap={result['mcap_cr']}Cr | pe={pe}")
        return result
        
    except requests.exceptions.Timeout:
        log.warning(f"[NSE DIRECT] Timeout for {base}")
        return None
    except Exception as e:
        log.warning(f"[NSE DIRECT] {base}: {e}")
        return None


def _nsetools_quote(symbol):
    """
    Fetch quote via nsetools library (wraps NSE APIs cleanly).
    Uses all_data=True to get securityInfo (shares) + metadata (PE).
    """
    base = symbol.replace(".NS", "").replace(".BO", "").upper()
    try:
        from nsetools import Nse
        nse = Nse()
        
        # all_data=True returns the full NSE response with securityInfo, metadata, etc.
        q = nse.get_quote(base, all_data=True)
        if not q:
            return None
        
        # The response structure from nsetools v2.0 with all_data=True:
        # {
        #   "priceInfo": { "lastPrice", "previousClose", "weekHighLow": {"min","max"}, ... },
        #   "securityInfo": { "issuedSize": 12345678, ... },
        #   "metadata": { "companyName", "industry", "pdSymbolPe", ... },
        #   "industryInfo": { "macro", "sector", "basicIndustry", ... },
        #   "info": { ... }  (in some versions)
        # }
        # BUT if all_data is not supported in this version, it returns flat dict:
        # { "lastPrice", "previousClose", "change", "pChange", "companyName", ... }
        
        pi = q.get("priceInfo", {}) or {}
        metadata = q.get("metadata", {}) or {}
        sec_info = q.get("securityInfo", {}) or {}
        ind_info = q.get("industryInfo", {}) or {}
        
        # Price — try nested first, then flat
        cmp = (pi.get("lastPrice") or pi.get("close") or 
               q.get("lastPrice") or q.get("close") or 0)
        
        if not cmp or cmp <= 0:
            return None
        
        prev_close = pi.get("previousClose") or q.get("previousClose") or 0
        change = q.get("change") or (round(cmp - prev_close, 2) if prev_close else 0)
        change_pct = q.get("pChange") or (round((change / prev_close) * 100, 2) if prev_close else 0)
        
        # 52-week high/low
        wk = pi.get("weekHighLow", {}) or q.get("weekHighLow", {}) or {}
        year_high = wk.get("max") or 0
        year_low = wk.get("min") or 0
        # Handle case where max/min might be dicts with 'value' key
        if isinstance(year_high, dict):
            year_high = year_high.get("value", 0)
        if isinstance(year_low, dict):
            year_low = year_low.get("value", 0)
        
        # Shares outstanding from securityInfo
        issued_size = sec_info.get("issuedSize") or sec_info.get("issuedCap") or 0
        try:
            issued_size = int(issued_size) if issued_size else 0
        except:
            issued_size = 0
        mcap = cmp * issued_size if issued_size else 0
        
        # PE from metadata
        pe = metadata.get("pdSymbolPe") or metadata.get("pe") or q.get("pe") or 0
        try:
            pe = float(str(pe).replace(",", "")) if pe else 0
        except:
            pe = 0
        
        eps = round(cmp / pe, 2) if pe and pe > 0 else 0
        
        # Company info
        company_name = (metadata.get("companyName") or 
                        q.get("companyName") or 
                        metadata.get("symbol") or base)
        sector = (ind_info.get("macro") or 
                  ind_info.get("sector") or 
                  metadata.get("industry") or "")
        industry = (ind_info.get("basicIndustry") or 
                    ind_info.get("industry") or "")
        
        result = {
            "cmp":          round(cmp, 2),
            "mcap_cr":      round(mcap / 1e7, 2) if mcap else 0,
            "shares_cr":    round(issued_size / 1e7, 2) if issued_size else 0,
            "pe":           round(pe, 2),
            "eps":          eps,
            "name":         company_name,
            "sector":       sector,
            "industry":     industry,
            "change":       round(change, 2) if isinstance(change, float) else change,
            "changePct":    round(change_pct, 2) if isinstance(change_pct, float) else change_pct,
            "yearHigh":     year_high,
            "yearLow":      year_low,
            "bookValue":    0,
            "dividendYield": 0,
            "currency":     "INR",
            "_source":      "nsetools",
            "_ticker":      base + ".NS",
        }
        
        log.info(f"[NSETOOLS] ✅ {base}: ₹{cmp} | mcap={result['mcap_cr']}Cr | pe={pe}")
        return result
        
    except ImportError:
        log.debug("[NSETOOLS] nsetools not installed")
        return None
    except Exception as e:
        log.warning(f"[NSETOOLS] {base}: {e}")
        return None


def _yf_quote_inner(symbol):
    """yfinance quote — LAST RESORT only, high rate limit risk from cloud IPs."""
    base = symbol.replace(".NS", "").replace(".BO", "")
    tickers_to_try = [base + ".NS", base + ".BO"]
    
    for ticker in tickers_to_try:
        err_key = f"err_{ticker}"
        if cached(err_key, ERROR_TTL) is not None:
            continue
        
        try:
            t = yf.Ticker(ticker)
            info = t.info
            
            if not info or len(info) < 5:
                break
            
            cmp = (info.get("regularMarketPrice") or
                   info.get("currentPrice") or
                   info.get("previousClose") or 0)
            if not cmp:
                break
            
            mcap = info.get("marketCap", 0)
            shares = (mcap / cmp) if cmp > 0 else 0
            
            result = {
                "cmp":          round(cmp, 2),
                "mcap_cr":      round(mcap / 1e7, 2),
                "shares_cr":    round(shares / 1e7, 2),
                "pe":           round(info.get("trailingPE", 0) or 0, 2),
                "eps":          round(info.get("trailingEps", 0) or 0, 2),
                "name":         info.get("longName") or info.get("shortName") or symbol,
                "sector":       info.get("sector") or "",
                "industry":     info.get("industry") or "",
                "change":       round(info.get("regularMarketChange", 0) or 0, 2),
                "changePct":    round(info.get("regularMarketChangePercent", 0) or 0, 2),
                "yearHigh":     info.get("fiftyTwoWeekHigh", 0),
                "yearLow":      info.get("fiftyTwoWeekLow", 0),
                "bookValue":    info.get("bookValue", 0),
                "dividendYield":round((info.get("dividendYield", 0) or 0) * 100, 2),
                "currency":     info.get("currency", "INR"),
                "_source":      "yfinance",
                "_ticker":      ticker,
            }
            log.info(f"[YF] ✅ {base}: ₹{cmp}")
            return result
            
        except Exception as e:
            err_str = str(e).lower()
            if "too many requests" in err_str or "rate limit" in err_str or "429" in err_str:
                log.warning(f"[YF RATE LIMIT] {ticker}")
                set_cache(f"err_{ticker}", True, ERROR_TTL)
                break
            else:
                log.error(f"[YF QUOTE ERROR] {ticker}: {e}")
    
    return None


# ── Track which source is working (auto-switch) ──
_yf_failures = 0  # count consecutive yfinance failures
YF_FAILURE_THRESHOLD = 3  # after 3 failures, skip yfinance for a while
_yf_skip_until = 0  # timestamp until which yfinance is skipped


def _enrich_with_yfinance(result, symbol):
    """
    If NSE quote is missing mcap/PE/EPS, fill from yfinance enrichment cache.
    Enrichment data (mcap, PE, sector, bookValue etc.) changes slowly,
    so we cache it for 6 hours separately from live price.
    """
    ENRICH_TTL = 21600  # 6 hours
    base = symbol.replace(".NS", "").replace(".BO", "").upper()
    eck = f"enrich:{base}"
    
    enrichment = cached(eck, ENRICH_TTL)
    if enrichment is None:
        # Try to fetch from yfinance (throttled)
        global _yf_last_call, _yf_failures, _yf_skip_until
        now = time.time()
        
        # Skip if yfinance is in cooldown
        if now < _yf_skip_until:
            log.debug(f"[ENRICH] Skipping yfinance for {base} — cooling down")
            return result
        
        # Throttle
        elapsed = now - _yf_last_call
        if elapsed < YF_MIN_INTERVAL:
            time.sleep(YF_MIN_INTERVAL - elapsed)
        _yf_last_call = time.time()
        
        for suffix in [".NS", ".BO"]:
            try:
                t = yf.Ticker(base + suffix)
                info = t.info
                if info and len(info) > 5 and (info.get("marketCap") or info.get("trailingPE")):
                    enrichment = {
                        "mcap":         info.get("marketCap", 0) or 0,
                        "pe":           info.get("trailingPE", 0) or 0,
                        "eps":          info.get("trailingEps", 0) or 0,
                        "shares":       info.get("sharesOutstanding", 0) or 0,
                        "bookValue":    info.get("bookValue", 0) or 0,
                        "dividendYield":info.get("dividendYield", 0) or 0,
                        "name":         info.get("longName") or info.get("shortName") or "",
                        "sector":       info.get("sector") or "",
                        "industry":     info.get("industry") or "",
                        "yearHigh":     info.get("fiftyTwoWeekHigh", 0) or 0,
                        "yearLow":      info.get("fiftyTwoWeekLow", 0) or 0,
                    }
                    set_cache(eck, enrichment, ENRICH_TTL)
                    # Also keep a stale copy for 7 days
                    set_cache(f"stale_enrich:{base}", enrichment, 604800)
                    _yf_failures = 0
                    log.info(f"[ENRICH] ✅ {base}: mcap={enrichment['mcap']}, pe={enrichment['pe']}")
                    break
            except Exception as e:
                err_str = str(e).lower()
                if "too many requests" in err_str or "rate limit" in err_str or "429" in err_str:
                    log.warning(f"[ENRICH RATE LIMIT] {base}")
                    set_cache(f"err_{base}.NS", True, ERROR_TTL)
                    _yf_failures += 1
                    if _yf_failures >= YF_FAILURE_THRESHOLD:
                        _yf_skip_until = time.time() + 300
                        log.warning(f"[ENRICH] yfinance failed {_yf_failures}x — skipping for 5 min")
                        _yf_failures = 0
                    break
                else:
                    log.debug(f"[ENRICH] {base}{suffix}: {e}")
        
        # If still no enrichment, try stale
        if enrichment is None:
            enrichment = cached(f"stale_enrich:{base}", 604800)
            if enrichment:
                log.info(f"[ENRICH] Serving stale enrichment for {base}")
    
    # Apply enrichment to the NSE result
    if enrichment:
        cmp = result.get("cmp", 0)
        mcap = enrichment.get("mcap", 0)
        shares = enrichment.get("shares", 0)
        
        if mcap and (not result.get("mcap_cr") or result["mcap_cr"] == 0):
            result["mcap_cr"] = round(mcap / 1e7, 2)
        if shares and (not result.get("shares_cr") or result["shares_cr"] == 0):
            result["shares_cr"] = round(shares / 1e7, 2)
        if not result.get("pe") or result["pe"] == 0:
            result["pe"] = round(enrichment.get("pe", 0), 2)
        if not result.get("eps") or result["eps"] == 0:
            result["eps"] = round(enrichment.get("eps", 0), 2)
        if not result.get("bookValue") or result["bookValue"] == 0:
            result["bookValue"] = enrichment.get("bookValue", 0)
        if not result.get("dividendYield") or result["dividendYield"] == 0:
            dy = enrichment.get("dividendYield", 0)
            result["dividendYield"] = round(dy * 100, 2) if dy and dy < 1 else round(dy, 2)
        if not result.get("sector"):
            result["sector"] = enrichment.get("sector", "")
        if not result.get("industry"):
            result["industry"] = enrichment.get("industry", "")
        if not result.get("name") or result["name"] == symbol.upper():
            name = enrichment.get("name", "")
            if name:
                result["name"] = name
        if enrichment.get("yearHigh") and (not result.get("yearHigh") or result["yearHigh"] == 0):
            result["yearHigh"] = enrichment["yearHigh"]
        if enrichment.get("yearLow") and (not result.get("yearLow") or result["yearLow"] == 0):
            result["yearLow"] = enrichment["yearLow"]
        
        result["_enriched"] = True
    
    return result


def yf_quote(symbol):
    """
    Multi-source quote fetcher:
      1. NSE Direct HTTP API (primary — no rate limits) 
      2. nsetools library (backup)
      3. yfinance (last resort — rate limited on cloud IPs)
    
    After getting a price from any source, enriches with mcap/PE/EPS
    from yfinance (cached 6 hours — these don't change every second).
    """
    global _yf_failures, _yf_skip_until
    result = None
    
    # Source 1: NSE Direct API
    try:
        result = _nse_direct_quote(symbol)
        if result and result.get("cmp", 0) > 0:
            return _enrich_with_yfinance(result, symbol)
    except Exception as e:
        log.debug(f"[QUOTE] NSE direct failed for {symbol}: {e}")
    
    # Source 2: nsetools library
    try:
        result = _nsetools_quote(symbol)
        if result and result.get("cmp", 0) > 0:
            return _enrich_with_yfinance(result, symbol)
    except Exception as e:
        log.debug(f"[QUOTE] nsetools failed for {symbol}: {e}")
    
    # Source 3: yfinance (skip if recently rate-limited)
    now = time.time()
    if now < _yf_skip_until:
        log.debug(f"[QUOTE] Skipping yfinance for {symbol} — cooling down")
    else:
        try:
            result = _yf_quote_inner(symbol)
            if result and result.get("cmp", 0) > 0:
                _yf_failures = 0  # reset on success
                return result  # yfinance already has all fields, no enrichment needed
            else:
                _yf_failures += 1
        except Exception as e:
            _yf_failures += 1
            log.debug(f"[QUOTE] yfinance failed for {symbol}: {e}")
        
        # If yfinance keeps failing, back off
        if _yf_failures >= YF_FAILURE_THRESHOLD:
            _yf_skip_until = now + 300  # skip yfinance for 5 min
            log.warning(f"[QUOTE] yfinance failed {_yf_failures}x — skipping for 5 min")
            _yf_failures = 0
    
    log.warning(f"[QUOTE] All sources failed for {symbol}")
    return None


def yf_financials(symbol):
    """
    Fetch annual financials (revenue + PAT).
    yfinance is the ONLY free source for this data.
    Cached for 72+ hours since annual results change quarterly.
    Throttled to max 1 yfinance call per 3 seconds globally.
    """
    global _yf_last_call
    ticker = symbol if "." in symbol else symbol + ".NS"
    
    # Global throttle: wait if we called yfinance too recently
    now = time.time()
    elapsed = now - _yf_last_call
    if elapsed < YF_MIN_INTERVAL:
        wait = YF_MIN_INTERVAL - elapsed
        log.debug(f"[YF FIN] Throttling {ticker} — waiting {wait:.1f}s")
        time.sleep(wait)
    
    _yf_last_call = time.time()
    
    try:
        t = yf.Ticker(ticker)
        inc = t.financials
        if inc is None or inc.empty:
            if not ticker.endswith(".BO"):
                ticker2 = symbol.replace(".NS", "") + ".BO"
                # Throttle again for second attempt
                time.sleep(YF_MIN_INTERVAL)
                _yf_last_call = time.time()
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
        log.info(f"[YF FIN] ✅ {ticker}: {len(years)} years fetched")
        return years
    except Exception as e:
        err_str = str(e).lower()
        if "too many requests" in err_str or "rate limit" in err_str or "429" in err_str:
            log.warning(f"[YF FIN RATE LIMIT] {ticker} — backing off")
            set_cache(f"err_{ticker}", True, 300)  # block this ticker for 5 min
        else:
            log.error(f"[YF FIN ERROR] {ticker}: {e}")
        return None


def yf_search(query):
    """Search stocks — uses NSE direct first, yfinance as fallback."""
    results = []
    
    # Try NSE direct search first
    try:
        s = _get_nse_session()
        if s:
            url = f"https://www.nseindia.com/api/search/autocomplete?q={query}"
            r = s.get(url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                for item in (data.get("symbols") or [])[:10]:
                    sym = item.get("symbol", "")
                    if sym:
                        results.append({
                            "sym": sym,
                            "name": item.get("symbol_info") or sym,
                            "sec": "NSE",
                        })
            if results:
                log.info(f"[SEARCH] NSE direct: {len(results)} results for '{query}'")
                return results[:15]
    except Exception as e:
        log.debug(f"[SEARCH] NSE direct failed: {e}")
    
    # Fallback: yfinance search
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


def calcValue(pat, gPct, rPct, n, pe):
    """DCF calculation: present value of future cash flows."""
    if pat <= 0 or pe <= 0 or n <= 0: return 0
    g, r = gPct / 100, rPct / 100
    pv = 0
    if abs(r - g) < 1e-6:
        for t in range(1, int(n) + 1):
            pv += (pat * math.pow(1 + g, t)) / math.pow(1 + r, t)
    else:
        pv = pat * (1 + g) * ((1 - math.pow(1 + g, n) * math.pow(1 + r, -n)) / (r - g))
    terminal = (pat * math.pow(1 + g, n) * pe) / math.pow(1 + r, n)
    return pv + terminal


def solveGrowth(pat, mcap, rPct, n, pe):
    """Reverse DCF: given market cap, solve for implied growth rate."""
    if pat <= 0 or mcap <= 0 or pe <= 0: return None
    lo, hi = -90, 200
    for _ in range(500):
        mid = (lo + hi) / 2
        val = calcValue(pat, mid, rPct, n, pe)
        if abs(val - mcap) < mcap * 0.000001:
            return round(mid, 2)
        if val < mcap:
            lo = mid
        else:
            hi = mid
    return round((lo + hi) / 2, 2)


# Stock API routes
@app.route("/api/search")
def search_stocks():
    q = request.args.get("q", "").strip()
    if not q or len(q) < 1: return jsonify([])
    ck = f"s:{q.lower()}"
    c = cached(ck, SEARCH_TTL)
    if c is not None: return jsonify(c)
    results = yf_search(q)
    set_cache(ck, results)
    return jsonify(results)


@app.route("/api/stocklist")
def stock_list():
    """Return ALL NSE stock symbols + names in one lightweight call. Cached 24h."""
    ck = "stocklist:v1"
    c = cached(ck, 86400)
    if c is not None:
        return jsonify(c)

    stocks = []
    try:
        from nsetools import Nse
        nse = Nse()
        all_stocks = nse.get_stock_codes()
        for sym, name in all_stocks.items():
            if sym == "SYMBOL" or not sym:
                continue
            stocks.append({"sym": sym, "name": name, "sec": "NSE"})
        if stocks:
            log.info(f"[STOCKLIST] nsetools: {len(stocks)} stocks")
            set_cache(ck, stocks, 86400)
            return jsonify(stocks)
    except Exception as e:
        log.debug(f"[STOCKLIST] nsetools failed: {e}")

    for idx in ["NIFTY%2050", "NIFTY%20NEXT%2050", "NIFTY%20MIDCAP%2050", "NIFTY%20BANK", "NIFTY%20IT", "NIFTY%20PHARMA"]:
        try:
            s = _get_nse_session()
            if not s: break
            r = s.get(f"https://www.nseindia.com/api/equity-stockIndices?index={idx}", timeout=8)
            if r.status_code == 200:
                data = r.json()
                for item in (data.get("data") or []):
                    sym = item.get("symbol", "")
                    name = item.get("meta", {}).get("companyName", "") or sym
                    if sym and not any(st["sym"] == sym for st in stocks):
                        stocks.append({"sym": sym, "name": name, "sec": "NSE"})
        except: continue

    if stocks:
        log.info(f"[STOCKLIST] Combined: {len(stocks)} stocks")
        set_cache(ck, stocks, 86400)
    return jsonify(stocks)


@app.route("/api/batch-prices", methods=["POST"])
def batch_prices():
    """Fetch live prices for multiple symbols at once. Used by watchlist/portfolio/screens.
    Accepts: {"symbols": ["RELIANCE","TCS",...]}
    Returns: {"RELIANCE": {"cmp": 1286, "mcap_cr": 870000, "pe": 23.5, "dayChangePct": 0.5}, ...}
    """
    data = request.get_json() or {}
    symbols = data.get("symbols", [])
    if not symbols or len(symbols) > 50:
        return jsonify({"error": "Provide 1-50 symbols"}), 400
    
    prices = {}
    for sym in symbols:
        sym = sym.upper().strip()
        if not sym:
            continue
        # Check cache first (quote cache, 5 min TTL)
        ck = f"bq:{sym}"
        c = cached(ck, 300)
        if c:
            prices[sym] = c
            continue
        
        # Fetch from nsetools (fast, no rate limit)
        try:
            from nsetools import Nse
            nse = Nse()
            q = nse.get_quote(sym)
            if q and q.get("lastPrice"):
                price_data = {
                    "cmp": q["lastPrice"],
                    "mcap_cr": round(q.get("totalTradedValue", 0) / 1e5, 2) if q.get("totalTradedValue") else 0,
                    "pe": q.get("pE", 0) or 0,
                    "dayChangePct": q.get("pChange", 0) or 0,
                }
                # Try to get mcap from other field
                if price_data["mcap_cr"] == 0 and q.get("issuedSize") and q.get("lastPrice"):
                    price_data["mcap_cr"] = round(q["issuedSize"] * q["lastPrice"] / 1e7, 2)
                prices[sym] = price_data
                set_cache(ck, price_data, 300)
                continue
        except Exception as e:
            log.debug(f"[BATCH] nsetools failed for {sym}: {e}")
        
        # Fallback: use existing fullstock cache
        fck = f"f:{sym}"
        fc = cached(fck, 600)
        if fc and fc.get("cmp"):
            prices[sym] = {
                "cmp": fc["cmp"],
                "mcap_cr": fc.get("mcapCr", 0),
                "pe": fc.get("pe", 0),
                "dayChangePct": fc.get("dayChangePct", 0),
            }
            continue
        
        # Last resort: quick yfinance
        try:
            t = yf.Ticker(f"{sym}.NS")
            info = t.info
            if info and info.get("regularMarketPrice"):
                price_data = {
                    "cmp": info["regularMarketPrice"],
                    "mcap_cr": round(info.get("marketCap", 0) / 1e7, 2),
                    "pe": info.get("trailingPE", 0) or 0,
                    "dayChangePct": round(((info.get("regularMarketPrice",0) - info.get("regularMarketPreviousClose",1)) / max(info.get("regularMarketPreviousClose",1),1)) * 100, 2),
                }
                prices[sym] = price_data
                set_cache(ck, price_data, 300)
        except Exception as e:
            log.debug(f"[BATCH] yf failed for {sym}: {e}")
    
    return jsonify(prices)


@app.route("/api/fullstock/<symbol>")
def fullstock(symbol):
    sym = symbol.upper().replace(".NS", "").replace(".BO", "")
    ck = f"f:{sym}"
    c = cached(ck, QUOTE_TTL)
    if c is not None: return jsonify(c)

    # Fetch; on rate limit serve stale so user still sees data
    quote = yf_quote(sym)
    if not quote:
        stale = cached(f"stale:{ck}", 3600)
        if stale:
            log.info(f"[FULLSTOCK] Serving stale cache for {sym}")
            return jsonify({**stale, "_stale": True})
    fck = f"fin:{sym}"
    years = cached(fck, FIN_TTL)
    if years is None:
        years = yf_financials(sym)
        if years:
            set_cache(fck, years, FIN_TTL)
            set_cache(f"stale_fin:{sym}", years, 604800)  # keep stale financials for 7 days
        else:
            # Serve stale financials rather than nothing
            years = cached(f"stale_fin:{sym}", 604800)
            if years:
                log.info(f"[FULLSTOCK] Serving stale financials for {sym}")
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
        "_source": {"quote": quote.get("_source", "unknown") if quote else "none", "financials": "yfinance" if years else "none", "years": len(years)},
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
    set_cache(f"stale:{ck}", result, STALE_TTL)  # keep stale copy for fallback
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

@app.route("/api/debug-quote/<symbol>")
def debug_quote(symbol):
    """Debug: show what each source returns for a symbol. Admin only in production."""
    sym = symbol.upper().replace(".NS", "").replace(".BO", "")
    result = {"symbol": sym, "sources": {}}
    
    # Test nsetools raw response
    try:
        from nsetools import Nse
        nse = Nse()
        raw = nse.get_quote(sym, all_data=True)
        if raw:
            # Show key fields (not full dump which is huge)
            result["sources"]["nsetools_raw_keys"] = list(raw.keys()) if isinstance(raw, dict) else "not_dict"
            if isinstance(raw, dict):
                for key in ["priceInfo", "securityInfo", "metadata", "industryInfo", "info"]:
                    sub = raw.get(key)
                    if sub and isinstance(sub, dict):
                        result["sources"][f"nsetools_{key}"] = {k: v for k, v in sub.items() if v is not None and v != "" and v != 0}
                # Also show flat-level price fields
                for key in ["lastPrice", "previousClose", "change", "pChange", "companyName", "pe"]:
                    if key in raw:
                        result["sources"][f"nsetools_flat_{key}"] = raw[key]
    except Exception as e:
        result["sources"]["nsetools_error"] = str(e)[:200]
    
    # Test NSE direct
    try:
        direct = _nse_direct_quote(sym)
        if direct:
            result["sources"]["nse_direct"] = {k: v for k, v in direct.items() if v}
        else:
            result["sources"]["nse_direct"] = "failed"
    except Exception as e:
        result["sources"]["nse_direct_error"] = str(e)[:200]
    
    # Enrichment cache status
    eck = f"enrich:{sym}"
    enrichment = cached(eck, 21600)
    result["sources"]["enrichment_cached"] = bool(enrichment)
    if enrichment:
        result["sources"]["enrichment_data"] = enrichment
    
    # Quote cache status
    ck = f"f:{sym}"
    fullstock_cache = cached(ck, QUOTE_TTL)
    result["sources"]["fullstock_cached"] = bool(fullstock_cache)
    
    return jsonify(result)

@app.route("/")
def health():
    return jsonify({
        "status": "ok", "service": "DIY Investing API v8",
        "source": "multi-source (NSE direct → nsetools → yfinance)",
        "features": ["auth", "google_oauth", "razorpay_links", "watchlist", "sentiment", "prop_research", "admin"],
        "db": "connected" if db.engine else "error",
    })


@app.route("/api/data-status")
def data_status():
    """Diagnostic: test all data sources individually."""
    status = {"timestamp": datetime.utcnow().isoformat(), "sources": {}}
    test_sym = "RELIANCE"
    
    # Test 1: NSE Direct
    try:
        t0 = time.time()
        r = _nse_direct_quote(test_sym)
        ms = round((time.time() - t0) * 1000)
        status["sources"]["nse_direct"] = {
            "working": bool(r and r.get("cmp", 0) > 0),
            "cmp": r.get("cmp") if r else 0,
            "latency_ms": ms,
        }
    except Exception as e:
        status["sources"]["nse_direct"] = {"working": False, "error": str(e)[:100]}
    
    # Test 2: nsetools
    try:
        t0 = time.time()
        r = _nsetools_quote(test_sym)
        ms = round((time.time() - t0) * 1000)
        status["sources"]["nsetools"] = {
            "working": bool(r and r.get("cmp", 0) > 0),
            "cmp": r.get("cmp") if r else 0,
            "latency_ms": ms,
        }
    except Exception as e:
        status["sources"]["nsetools"] = {"working": False, "error": str(e)[:100]}
    
    # Test 3: yfinance (quote)
    try:
        t0 = time.time()
        r = _yf_quote_inner(test_sym)
        ms = round((time.time() - t0) * 1000)
        status["sources"]["yfinance_quote"] = {
            "working": bool(r and r.get("cmp", 0) > 0),
            "cmp": r.get("cmp") if r else 0,
            "latency_ms": ms,
        }
    except Exception as e:
        status["sources"]["yfinance_quote"] = {"working": False, "error": str(e)[:100]}
    
    # Test 4: yfinance (financials)
    try:
        t0 = time.time()
        fin_cache = cached(f"fin:{test_sym}", FIN_TTL)
        if fin_cache:
            status["sources"]["yfinance_financials"] = {
                "working": True,
                "years": len(fin_cache),
                "cached": True,
                "note": "Serving from cache (72h TTL)",
            }
        else:
            years = yf_financials(test_sym)
            ms = round((time.time() - t0) * 1000)
            status["sources"]["yfinance_financials"] = {
                "working": bool(years),
                "years": len(years) if years else 0,
                "cached": False,
                "latency_ms": ms,
            }
    except Exception as e:
        status["sources"]["yfinance_financials"] = {"working": False, "error": str(e)[:100]}
    
    # Cache stats
    status["cache"] = {
        "memory_keys": len(cache),
        "yf_failures": _yf_failures,
        "yf_skip_until": _yf_skip_until,
        "yf_skipping": time.time() < _yf_skip_until,
    }
    try:
        db_cache_count = StockCache.query.count()
        status["cache"]["db_keys"] = db_cache_count
    except:
        status["cache"]["db_keys"] = "error"
    
    return jsonify(status)


@app.route("/api/test")
def test_api():
    result = {"status": "ok", "tests": {}}
    try:
        q = yf_quote("TCS")
        result["tests"]["quote"] = {
            "working": bool(q and q["cmp"] > 0),
            "tcs_cmp": q["cmp"] if q else 0,
            "source": q.get("_source", "unknown") if q else "failed",
        }
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
