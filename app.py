
import re
import json
import secrets
import ipaddress
import unicodedata
import logging
import pickle
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlparse, urlunparse

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
SUSPICIOUS_QUERY_KEYS = (
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "return",
    "target",
    "url",
)
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy import inspect, text
from flask_wtf.csrf import CSRFError, CSRFProtect

load_dotenv()

from config import Config
from database.models import Feedback, Scan, User, db


login_manager = LoginManager()
oauth = OAuth()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
THREAT_CACHE_TTL_SECONDS = 900
threat_cache = {"data": None, "fetched_at": None}
RECENT_BREACHES_BASE_URL = "https://recentbreaches.com/api"
REALTIME_CACHE_TTL_SECONDS = 600
realtime_cache = {"data": None, "fetched_at": None}
URL_MODEL_PATH = Path(__file__).parent / "models" / "url_model.joblib"
url_model_artifact = None
SUSPICIOUS_URL_TERMS = (
    "account-verify",
    "confirm-login",
    "password-reset",
    "secure-update",
    "wallet-connect",
    "free-prize",
)
URGENT_MESSAGE_TERMS = (
    "urgent",
    "immediately",
    "right now",
    "act now",
    "action required",
    "final notice",
)
IMPERSONATION_TERMS = (
    "bank",
    "account support",
    "security team",
    "customer service",
    "government",
    "tax department",
    "ceo",
    "manager",
)
CREDENTIAL_MESSAGE_TERMS = (
    "verify your account",
    "verify your identity",
    "password",
    "one-time password",
    "otp",
    "verification code",
    "login",
)
PAYMENT_MESSAGE_TERMS = (
    "gift card",
    "send money",
    "wire transfer",
    "bank transfer",
    "crypto",
    "bitcoin",
    "pay a fee",
    "payment",
)
SUSPICIOUS_LINK_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
)


def predict_url_model(value):
    if not url_model_artifact:
        return None
    model = url_model_artifact["model"]
    probabilities = model.predict_proba([value])[0]
    classes = model.classes_
    best_index = probabilities.argmax()
    return str(classes[best_index]), float(probabilities[best_index])


def load_url_model():
    try:
        from ml.url_model import load_artifact
    except ModuleNotFoundError as error:
        if error.name in {"joblib", "numpy", "pandas", "scipy", "sklearn"}:
            logging.getLogger(__name__).warning(
                "URL model dependencies are unavailable; using rule-based scanning: %s",
                error,
            )
            return None
        raise

    try:
        return load_artifact(URL_MODEL_PATH)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        EOFError,
        ModuleNotFoundError,
        pickle.UnpicklingError,
    ) as error:
        logging.getLogger(__name__).warning("URL model unavailable: %s", error)
        return None


def analyze_scan(scan_type, value):
    reasons = []
    score = 0
    model_label = None
    model_confidence = None

    if scan_type == "url":
        parsed = urlparse(value)
        hostname = parsed.hostname or ""
        if parsed.scheme != "https":
            score += 20
            reasons.append("The link does not use HTTPS.")
        if len(value) > 120:
            score += 10
            reasons.append("The URL is unusually long.")
        if any(term in value.lower() for term in SUSPICIOUS_URL_TERMS):
            score += 30
            reasons.append("The URL contains language commonly used in phishing.")
        if hostname.count(".") > 3:
            score += 15
            reasons.append("The hostname contains an unusual number of subdomains.")
        if "xn--" in hostname.lower():
            score += 25
            reasons.append("The hostname uses punycode, which can hide look-alike domains.")
        if any(ord(character) > 127 for character in hostname):
            score += 20
            reasons.append("The hostname contains non-ASCII characters that may imitate another domain.")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            score += 35
            reasons.append("The link uses an IP address instead of a normal domain.")
        query = parse_qs(parsed.query, keep_blank_values=True)
        redirect_keys = set(query).intersection(SUSPICIOUS_QUERY_KEYS)
        if redirect_keys:
            score += 20
            reasons.append("The URL contains a redirect parameter that can hide the final destination.")
        if any(
            "http://" in item.lower() or "https://" in item.lower()
            for values in query.values()
            for item in values
        ):
            score += 15
            reasons.append("The query string contains another URL.")
        model_prediction = predict_url_model(value)
        if model_prediction:
            model_label, model_confidence = model_prediction
            reasons.append(
                f"ML baseline classified this URL as {model_label} "
                f"({model_confidence:.0%} confidence)."
            )
            if model_label == "dangerous" and model_confidence >= 0.65:
                score = max(score, round(60 + model_confidence * 40))
            elif model_label == "suspicious" and model_confidence >= 0.45:
                score = max(score, round(25 + model_confidence * 35))
    else:
        lowered_value = value.lower()
        if any(term in lowered_value for term in URGENT_MESSAGE_TERMS):
            score += 20
            reasons.append("The message creates urgency or pressure to act quickly.")
        if any(term in lowered_value for term in IMPERSONATION_TERMS):
            score += 15
            reasons.append("The message may be impersonating an organization or authority.")
        if any(term in lowered_value for term in CREDENTIAL_MESSAGE_TERMS):
            score += 25
            reasons.append("The message requests or references account credentials or verification codes.")
        if any(term in lowered_value for term in PAYMENT_MESSAGE_TERMS):
            score += 25
            reasons.append("The message asks for money, payment, or a financial transfer.")
        if "http://" in lowered_value or "https://" in lowered_value:
            score += 15
            reasons.append("The message contains a link that should be checked before opening.")
        if any(domain in lowered_value for domain in SUSPICIOUS_LINK_DOMAINS):
            score += 20
            reasons.append("The message contains a URL-shortening service often used to hide destinations.")
        if value.count("!") >= 3:
            score += 10
            reasons.append("The message uses repeated exclamation marks to create pressure.")
        uppercase_letters = sum(character.isupper() for character in value)
        alphabetic_letters = sum(character.isalpha() for character in value)
        if alphabetic_letters >= 20 and uppercase_letters / alphabetic_letters > 0.6:
            score += 10
            reasons.append("The message uses unusually aggressive capitalization.")

    score = min(score, 100)
    classification = (
        "Dangerous" if score >= 60
        else "Suspicious" if score >= 25
        else "Safe"
    )
    if not reasons:
        reasons.append("No high-risk patterns were found by the initial checks.")
    return score, classification, reasons, model_label, model_confidence


def normalize_url(value):
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not supported.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from error

    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if port and not (
        (parsed.scheme.lower() == "http" and port == 80)
        or (parsed.scheme.lower() == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    path = unicodedata.normalize("NFC", path)
    return urlunparse((
        parsed.scheme.lower(),
        netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))


def create_app(config_object=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    oauth.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    Talisman(
        app,
        force_https=app.config.get("FORCE_HTTPS", False),
        strict_transport_security=app.config.get("FORCE_HTTPS", False),
        session_cookie_secure=app.config.get("SESSION_COOKIE_SECURE", False),
    )

    with app.app_context():
        db.create_all()
        if "google_id" not in {column["name"] for column in inspect(db.engine).get_columns("users")}:
            db.session.execute(text("ALTER TABLE users ADD COLUMN google_id VARCHAR(255)"))
            db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_google_id ON users (google_id)"))
            db.session.commit()
        scan_columns = {
            column["name"] for column in inspect(db.engine).get_columns("scans")
        }
        if "model_label" not in scan_columns:
            db.session.execute(text("ALTER TABLE scans ADD COLUMN model_label VARCHAR(20)"))
        if "model_confidence" not in scan_columns:
            db.session.execute(text("ALTER TABLE scans ADD COLUMN model_confidence FLOAT"))
        db.session.commit()

    global url_model_artifact
    if URL_MODEL_PATH.exists():
        url_model_artifact = load_url_model()

    if app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"):
        oauth.register(
            name="google",
            server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
            client_kwargs={"scope": "openid email profile"},
        )

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login"))

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return jsonify({"error": "Security validation failed. Refresh the page and try again."}), 400

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/login")
    def login():
        return render_template("login.html")

    @app.route("/signup")
    def signup():
        return render_template("signup.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.get("/auth/google")
    def google_login():
        if not app.config.get("GOOGLE_CLIENT_ID") or not app.config.get("GOOGLE_CLIENT_SECRET"):
            return "Google sign-in is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.", 503
        redirect_uri = url_for("google_callback", _external=True)
        return oauth.create_client("google").authorize_redirect(redirect_uri)

    @app.get("/auth/google/callback")
    def google_callback():
        if not app.config.get("GOOGLE_CLIENT_ID") or not app.config.get("GOOGLE_CLIENT_SECRET"):
            return "Google sign-in is not configured.", 503

        google = oauth.create_client("google")
        token = google.authorize_access_token()
        user_info = token.get("userinfo") or google.userinfo()
        google_id = user_info.get("sub")
        email = str(user_info.get("email", "")).strip().lower()
        name = str(user_info.get("name") or user_info.get("given_name") or "Google User").strip()

        if not google_id or not email or user_info.get("email_verified") is not True:
            return "Google did not provide a verified email address.", 400

        user = db.session.scalar(db.select(User).filter_by(google_id=google_id))
        if user is None:
            user = db.session.scalar(db.select(User).filter_by(email=email))
            if user is not None:
                if user.google_id and user.google_id != google_id:
                    return "This email is already linked to a different Google account.", 409
                user.google_id = google_id
            else:
                user = User()
                user.name = name[:100]
                user.email = email
                user.google_id = google_id
                user.set_password(secrets.token_urlsafe(32))
                db.session.add(user)

        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/threats")
    @login_required
    def threats():
        return render_template("threats.html")

    @app.post("/api/auth/signup")
    @limiter.limit("5 per minute")
    def api_signup():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password")
        terms_accepted = payload.get("termsAccepted") is True

        if not name or len(name) > 100:
            return jsonify({"error": "Enter a name between 1 and 100 characters."}), 400
        if not EMAIL_PATTERN.fullmatch(email):
            return jsonify({"error": "Enter a valid email address."}), 400
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            return jsonify({"error": "Password must be between 8 and 128 characters."}), 400
        if not terms_accepted:
            return jsonify({"error": "You must accept the terms and privacy policy."}), 400
        if db.session.scalar(db.select(User).filter_by(email=email)):
            return jsonify({"error": "An account with that email already exists."}), 409

        user = User()
        user.name = name
        user.email = email
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return jsonify({"user": user.to_dict()}), 201

    @app.post("/api/auth/login")
    @limiter.limit("10 per minute")
    def api_login():
        payload = request.get_json(silent=True) or {}
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password")
        user = db.session.scalar(db.select(User).filter_by(email=email))

        if not user or not isinstance(password, str) or not user.check_password(password):
            return jsonify({"error": "Invalid email or password."}), 401

        login_user(user, remember=payload.get("remember") is True)
        return jsonify({"user": user.to_dict()})

    @app.post("/api/auth/logout")
    @login_required
    @limiter.limit("20 per minute")
    def api_logout():
        logout_user()
        return jsonify({"message": "Logged out successfully."})

    @app.get("/api/auth/me")
    @login_required
    def api_me():
        return jsonify({"user": current_user.to_dict()})

    @app.post("/api/scans")
    @login_required
    @limiter.limit("30 per minute")
    def api_create_scan():
        payload = request.get_json(silent=True) or {}
        scan_type = str(payload.get("type", "")).strip().lower()
        value = str(payload.get("value", "")).strip()

        if scan_type not in {"url", "message"}:
            return jsonify({"error": "Scan type must be url or message."}), 400
        if not value:
            return jsonify({"error": "Enter something to scan."}), 400
        if scan_type == "url":
            if len(value) > 2048:
                return jsonify({"error": "URL must be 2,048 characters or fewer."}), 400
            try:
                value = normalize_url(value)
            except ValueError as error:
                return jsonify({"error": str(error)}), 400
        elif len(value) > 10000:
            return jsonify({"error": "Message must be 10,000 characters or fewer."}), 400

        (
            risk_score,
            classification,
            reasons,
            model_label,
            model_confidence,
        ) = analyze_scan(scan_type, value)
        scan = Scan()
        scan.user_id = current_user.id
        scan.scan_type = scan_type
        scan.input_text = value
        scan.risk_score = risk_score
        scan.classification = classification
        scan.reasons = "\n".join(reasons)
        scan.model_label = model_label
        scan.model_confidence = model_confidence
        db.session.add(scan)
        db.session.commit()
        return jsonify({"scan": scan.to_dict()}), 201

    @app.get("/api/scans")
    @login_required
    def api_scan_history():
        try:
            limit = min(max(int(request.args.get("limit", 20)), 1), 100)
        except (TypeError, ValueError):
            return jsonify({"error": "Limit must be a number between 1 and 100."}), 400

        user_scans = db.session.scalars(
            db.select(Scan)
            .where(Scan.user_id == current_user.id)
            .order_by(Scan.created_at.desc())
        ).all()
        counts = Counter(scan.classification for scan in user_scans)
        daily_counts = Counter(
            scan.created_at.date().isoformat()
            for scan in user_scans
            if scan.created_at
        )
        return jsonify({
            "scans": [scan.to_dict() for scan in user_scans[:limit]],
            "summary": {
                "total": len(user_scans),
                "safe": counts.get("Safe", 0),
                "suspicious": counts.get("Suspicious", 0),
                "dangerous": counts.get("Dangerous", 0),
                "daily": dict(sorted(daily_counts.items())[-7:]),
            },
        })

    @app.get("/api/analytics")
    @login_required
    def api_analytics():
        now = datetime.now(timezone.utc)
        today = now.date()
        user_scans = db.session.scalars(
            db.select(Scan)
            .where(Scan.user_id == current_user.id)
            .order_by(Scan.created_at.asc())
        ).all()

        daily = []
        for offset in range(6, -1, -1):
            current_date = today - timedelta(days=offset)
            matching = [
                scan for scan in user_scans
                if scan.created_at and scan.created_at.date() == current_date
            ]
            daily.append({
                "date": current_date.isoformat(),
                "count": len(matching),
                "safe": sum(scan.classification == "Safe" for scan in matching),
                "suspicious": sum(
                    scan.classification in {"Suspicious", "Dangerous"}
                    for scan in matching
                ),
            })

        current_week = today - timedelta(days=today.weekday())
        weekly = []
        for offset in range(3, -1, -1):
            week_start = current_week - timedelta(weeks=offset)
            week_end = week_start + timedelta(days=7)
            matching = [
                scan for scan in user_scans
                if scan.created_at
                and week_start <= scan.created_at.date() < week_end
            ]
            weekly.append({
                "week_start": week_start.isoformat(),
                "count": len(matching),
            })

        classification_counts = Counter(scan.classification for scan in user_scans)
        type_counts = Counter(scan.scan_type for scan in user_scans)
        return jsonify({
            "total_scans": len(user_scans),
            "average_risk": round(
                sum(scan.risk_score for scan in user_scans) / len(user_scans),
                2,
            ) if user_scans else 0,
            "classification_counts": {
                "safe": classification_counts.get("Safe", 0),
                "suspicious": classification_counts.get("Suspicious", 0),
                "dangerous": classification_counts.get("Dangerous", 0),
            },
            "type_counts": {
                "url": type_counts.get("url", 0),
                "message": type_counts.get("message", 0),
            },
            "charts": {
                "daily_scans": daily,
                "weekly_scans": weekly,
            },
        })

    @app.post("/api/feedback")
    @login_required
    @limiter.limit("5 per minute")
    def api_feedback():
        payload = request.get_json(silent=True) or {}
        email = str(payload.get("email", "")).strip().lower()
        message = str(payload.get("message", "")).strip()

        if not EMAIL_PATTERN.fullmatch(email):
            return jsonify({"error": "Enter a valid email address."}), 400
        if not message:
            return jsonify({"error": "Feedback message cannot be empty."}), 400
        if len(message) > 5000:
            return jsonify({"error": "Feedback message must be 5,000 characters or fewer."}), 400

        feedback = Feedback()
        feedback.user_id = current_user.id
        feedback.email = email
        feedback.message = message
        db.session.add(feedback)
        db.session.commit()
        return jsonify({"message": "Thank you for your feedback."}), 201

    @app.get("/api/threats/summary")
    @login_required
    def api_threat_summary():
        now = datetime.now(timezone.utc)
        cached_data = threat_cache["data"]
        fetched_at = threat_cache["fetched_at"]

        if cached_data and fetched_at and (now - fetched_at).total_seconds() < THREAT_CACHE_TTL_SECONDS:
            return jsonify(cached_data)

        try:
            request_headers = {"User-Agent": "ScamShield-AI/1.0"}
            with urlopen(Request(CISA_KEV_URL, headers=request_headers), timeout=10) as response:
                payload = json.loads(response.read())
            vulnerabilities = payload["vulnerabilities"]
            latest = sorted(
                vulnerabilities,
                key=lambda item: item.get("dateAdded", ""),
                reverse=True,
            )[:3]
            vendor_counts = Counter(
                item.get("vendorProject", "Unknown")
                for item in vulnerabilities
            )
            monthly_counts = Counter(
                item.get("dateAdded", "")[:7]
                for item in vulnerabilities
                if item.get("dateAdded")
            )
            data = {
                "source": "CISA Known Exploited Vulnerabilities",
                "count": len(vulnerabilities),
                "catalog_version": payload.get("catalogVersion"),
                "fetched_at": now.isoformat(),
                "ransomware_campaign_count": sum(
                    item.get("knownRansomwareCampaignUse") == "Known"
                    for item in vulnerabilities
                ),
                "vendor_counts": dict(vendor_counts.most_common(8)),
                "monthly_counts": dict(sorted(monthly_counts.items())[-12:]),
                "latest": [
                    {
                        "cve_id": item.get("cveID"),
                        "vendor": item.get("vendorProject"),
                        "product": item.get("product"),
                        "date_added": item.get("dateAdded"),
                    }
                    for item in latest
                ],
            }
        except (URLError, TimeoutError, ValueError, KeyError, TypeError) as error:
            if cached_data:
                return jsonify({
                    **cached_data,
                    "stale": True,
                    "error": f"Threat feed refresh failed: {error}",
                })
            return jsonify({"error": f"Threat feed unavailable: {error}"}), 503

        threat_cache["data"] = data
        threat_cache["fetched_at"] = now
        return jsonify(data)

    @app.get("/api/realtime")
    @login_required
    def api_realtime():
        now = datetime.now(timezone.utc)
        cached_data = realtime_cache["data"]
        fetched_at = realtime_cache["fetched_at"]

        if cached_data and fetched_at and (
            now - fetched_at
        ).total_seconds() < REALTIME_CACHE_TTL_SECONDS:
            return jsonify(cached_data)

        endpoint_urls = {
            "index": f"{RECENT_BREACHES_BASE_URL}/index",
            "geo": f"{RECENT_BREACHES_BASE_URL}/geo?window=28d",
            "series": f"{RECENT_BREACHES_BASE_URL}/series?days=28",
            "actors": f"{RECENT_BREACHES_BASE_URL}/actors?limit=10",
            "breaches": f"{RECENT_BREACHES_BASE_URL}/breaches?limit=25",
            "leaks": f"{RECENT_BREACHES_BASE_URL}/leaks",
        }
        responses = {}
        errors = {}

        def fetch_endpoint(name, endpoint_url):
            request_headers = {"User-Agent": "ScamShield-AI/1.0"}
            with urlopen(Request(endpoint_url, headers=request_headers), timeout=10) as response:
                body = json.loads(response.read())
            if isinstance(body, dict) and "error" in body:
                raise ValueError(body["error"])
            return name, body

        with ThreadPoolExecutor(max_workers=len(endpoint_urls)) as executor:
            futures = {
                executor.submit(fetch_endpoint, name, endpoint_url): name
                for name, endpoint_url in endpoint_urls.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    response_name, body = future.result()
                    responses[response_name] = body
                except (URLError, TimeoutError, ValueError, TypeError, json.JSONDecodeError) as error:
                    errors[name] = str(error)

        if not responses:
            if cached_data:
                return jsonify({**cached_data, "stale": True, "errors": errors})
            return jsonify({"error": "Realtime threat data is unavailable.", "errors": errors}), 503

        data = {
            "source": "Recent Breaches",
            "source_url": "https://recentbreaches.com/developers",
            "fetched_at": now.isoformat(),
            "stale": bool(errors),
            "errors": errors,
            **responses,
        }
        realtime_cache["data"] = data
        realtime_cache["fetched_at"] = now
        return jsonify(data)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
