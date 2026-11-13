import json

import pytest

import app as app_module
from app import create_app
from database.models import Feedback, Scan, User, db


@pytest.fixture
def client(tmp_path):
    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-secret"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False

    app = create_app(TestConfig)
    with app.test_client() as test_client:
        yield test_client
    with app.app_context():
        db.drop_all()


def signup(client, name="Test User", email="test@example.com", password="password123"):
    return client.post(
        "/api/auth/signup",
        json={
            "name": name,
            "email": email,
            "password": password,
            "termsAccepted": True,
        },
    )


def test_signup_hashes_password_and_creates_session(client):
    response = signup(client)

    assert response.status_code == 201
    assert response.json["user"]["email"] == "test@example.com"
    with client.application.app_context():
        user = db.session.scalar(db.select(User).filter_by(email="test@example.com"))
        assert user is not None
        assert user.password_hash != "password123"
        assert user.check_password("password123")

    assert client.get("/api/auth/me").json["user"]["name"] == "Test User"


def test_signup_rejects_duplicate_email(client):
    signup(client)

    response = signup(client, email="TEST@example.com")

    assert response.status_code == 409
    assert response.json == {"error": "An account with that email already exists."}


def test_login_and_logout(client):
    signup(client)
    client.post("/api/auth/logout")

    response = client.post(
        "/api/auth/login",
        json={
            "email": "TEST@example.com",
            "password": "password123",
            "remember": True,
        },
    )

    assert response.status_code == 200
    assert response.json["user"]["email"] == "test@example.com"
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_login_rejects_invalid_password(client):
    signup(client)

    response = client.post(
        "/api/auth/login",
        json={"email": "test@example.com", "password": "wrongpass"},
    )

    assert response.status_code == 401
    assert response.json == {"error": "Invalid email or password."}


def test_authentication_validates_signup_input(client):
    response = client.post(
        "/api/auth/signup",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "password": "short",
            "termsAccepted": False,
        },
    )

    assert response.status_code == 400


def test_dashboard_requires_login_and_is_available_after_signup(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    signup(client)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"Your security overview" in response.data


def test_google_sign_in_is_available_on_auth_pages_and_requires_configuration(client):
    assert b"Continue with Google" in client.get("/signup").data
    assert b"Continue with Google" in client.get("/login").data
    assert client.get("/auth/google").status_code == 503


def test_scan_is_saved_and_returned_in_user_history(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={"type": "url", "value": "http://secure-update.example.com/login"},
    )

    assert response.status_code == 201
    assert response.json["scan"]["classification"] == "Suspicious"
    assert response.json["scan"]["risk_score"] > 0
    assert response.json["scan"]["model_prediction"] in {
        "safe",
        "suspicious",
        "dangerous",
    }
    assert 0 <= response.json["scan"]["model_confidence"] <= 1

    history = client.get("/api/scans")
    assert history.status_code == 200
    assert history.json["summary"]["total"] == 1
    assert history.json["summary"]["suspicious"] == 1
    assert len(history.json["scans"]) == 1

    with client.application.app_context():
        assert db.session.scalar(db.select(Scan)) is not None


def test_scan_validation_rejects_invalid_url(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={"type": "url", "value": "javascript:alert(1)"},
    )

    assert response.status_code == 400
    assert response.json == {"error": "Enter a valid HTTP or HTTPS URL."}


def test_scan_normalizes_urls_and_detects_redirect_patterns(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={
            "type": "url",
            "value": "HTTPS://Example.COM/login?next=https://fake.example",
        },
    )

    assert response.status_code == 201
    scan = response.json["scan"]
    assert scan["input"] == "https://example.com/login?next=https://fake.example"
    assert scan["classification"] == "Suspicious"
    assert any("redirect parameter" in reason for reason in scan["reasons"])
    assert any("another URL" in reason for reason in scan["reasons"])


def test_scan_rejects_url_credentials(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={"type": "url", "value": "https://user:password@example.com"},
    )

    assert response.status_code == 400
    assert response.json == {
        "error": "URLs containing usernames or passwords are not supported."
    }


def test_message_scan_detects_credential_and_payment_pressure(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={
            "type": "message",
            "value": (
                "URGENT! Your bank security team needs your OTP immediately. "
                "Send a gift card payment right now!"
            ),
        },
    )

    assert response.status_code == 201
    scan = response.json["scan"]
    assert scan["classification"] == "Dangerous"
    assert scan["risk_score"] >= 60
    assert any("credentials" in reason for reason in scan["reasons"])
    assert any("financial transfer" in reason for reason in scan["reasons"])


def test_message_scan_allows_neutral_messages(client):
    signup(client)

    response = client.post(
        "/api/scans",
        json={"type": "message", "value": "Can we meet for lunch tomorrow?"},
    )

    assert response.status_code == 201
    assert response.json["scan"]["classification"] == "Safe"
    assert response.json["scan"]["risk_score"] == 0


def test_scan_history_is_private_to_current_user(client):
    signup(client)
    client.post("/api/scans", json={"type": "message", "value": "hello"})
    client.post("/api/auth/logout")
    signup(client, name="Other User", email="other@example.com")

    history = client.get("/api/scans")

    assert history.status_code == 200
    assert history.json["summary"]["total"] == 0
    assert history.json["scans"] == []


def test_feedback_is_saved_for_authenticated_user(client):
    signup(client)

    response = client.post(
        "/api/feedback",
        json={
            "email": "feedback@example.com",
            "message": "The scanner is helpful.",
        },
    )

    assert response.status_code == 201
    assert response.json == {"message": "Thank you for your feedback."}
    with client.application.app_context():
        feedback = db.session.scalar(db.select(Feedback))
        assert feedback is not None
        assert feedback.email == "feedback@example.com"
        assert feedback.message == "The scanner is helpful."


def test_feedback_validates_email_and_message(client):
    signup(client)

    response = client.post(
        "/api/feedback",
        json={"email": "not-an-email", "message": ""},
    )

    assert response.status_code == 400
    assert response.json == {"error": "Enter a valid email address."}


def test_feedback_requires_authentication(client):
    response = client.post(
        "/api/feedback",
        json={"email": "feedback@example.com", "message": "Hello"},
    )

    assert response.status_code == 401


def test_csrf_rejects_state_changing_request_without_token(tmp_path):
    class CsrfConfig:
        TESTING = True
        SECRET_KEY = "csrf-test-secret"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'csrf.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        WTF_CSRF_ENABLED = True
        RATELIMIT_ENABLED = False

    app = create_app(CsrfConfig)
    with app.test_client() as csrf_client:
        response = csrf_client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )

    assert response.status_code == 400
    assert response.json == {
        "error": "Security validation failed. Refresh the page and try again."
    }
    with app.app_context():
        db.drop_all()


def test_login_rate_limit_returns_too_many_requests(tmp_path):
    class RateLimitConfig:
        TESTING = True
        SECRET_KEY = "rate-limit-test-secret"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'rate-limit.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = True
        RATELIMIT_STORAGE_URI = "memory://"

    app = create_app(RateLimitConfig)
    with app.test_client() as rate_client:
        responses = [
            rate_client.post(
                "/api/auth/login",
                json={"email": "test@example.com", "password": "wrongpass"},
            )
            for _ in range(11)
        ]

    assert responses[-1].status_code == 429
    with app.app_context():
        db.drop_all()


def test_analytics_returns_empty_chart_ready_series(client):
    signup(client)

    response = client.get("/api/analytics")

    assert response.status_code == 200
    assert response.json["total_scans"] == 0
    assert response.json["average_risk"] == 0
    assert response.json["classification_counts"] == {
        "safe": 0,
        "suspicious": 0,
        "dangerous": 0,
    }
    assert len(response.json["charts"]["daily_scans"]) == 7
    assert len(response.json["charts"]["weekly_scans"]) == 4
    assert all(item["count"] == 0 for item in response.json["charts"]["daily_scans"])


def test_analytics_aggregates_scan_history(client):
    signup(client)
    client.post("/api/scans", json={"type": "url", "value": "https://example.com"})
    client.post(
        "/api/scans",
        json={"type": "message", "value": "URGENT! Send money now!"},
    )

    response = client.get("/api/analytics")

    assert response.status_code == 200
    assert response.json["total_scans"] == 2
    assert response.json["type_counts"] == {"url": 1, "message": 1}
    assert response.json["classification_counts"]["safe"] == 1
    assert response.json["classification_counts"]["suspicious"] == 1
    assert sum(item["count"] for item in response.json["charts"]["daily_scans"]) == 2


def test_threat_summary_uses_live_feed_data(client, monkeypatch):
    signup(client)
    payload = {
        "catalogVersion": "2026.11.1",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1",
                "vendorProject": "Example",
                "product": "Example Product",
                "dateAdded": "2026-11-12",
            }
        ],
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return json.dumps(payload).encode()

    app_module.threat_cache["data"] = None
    app_module.threat_cache["fetched_at"] = None
    monkeypatch.setattr(app_module, "urlopen", lambda request, timeout: FakeResponse())

    response = client.get("/api/threats/summary")

    assert response.status_code == 200
    assert response.json["count"] == 1
    assert response.json["latest"][0]["cve_id"] == "CVE-2026-1"


def test_realtime_endpoint_aggregates_public_api_data(client, monkeypatch):
    signup(client)
    responses = {
        "/index": {
            "index_today": 12,
            "count_24h": 3,
            "ransomware_7d": 2,
            "records_leaked_7d": "1K",
            "updated": "2026-11-13T00:00:00Z",
        },
        "/geo?window=28d": {
            "targets": [{"country": "India", "count": 4}],
            "origins": [],
        },
        "/series?days=28": {"items": [{"date": "2026-11-13", "count": 3, "records": 1}]},
        "/actors?limit=10": [{"name": "Example Group", "count": 2}],
        "/breaches?limit=25": [{"title": "Example incident", "severity": "high"}],
        "/leaks": {"leaks": [{"group": "Example Group", "victim": "Example"}]},
    }

    class FakeResponse:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return json.dumps(self.body).encode()

    def fake_urlopen(request, timeout):
        for suffix, body in responses.items():
            if request.full_url.endswith(suffix):
                return FakeResponse(body)
        raise AssertionError(request.full_url)

    app_module.realtime_cache["data"] = None
    app_module.realtime_cache["fetched_at"] = None
    monkeypatch.setattr(app_module, "urlopen", fake_urlopen)

    response = client.get("/api/realtime")

    assert response.status_code == 200
    assert response.json["index"]["count_24h"] == 3
    assert response.json["geo"]["targets"][0]["country"] == "India"
    assert response.json["breaches"][0]["title"] == "Example incident"
