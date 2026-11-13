# ScamShield-AI Backend Checklist

## 1. Project foundation

- [X] Add backend dependencies to `requirements.txt`:
  - [X] Flask
  - [X] Flask-SQLAlchemy
  - [X] Flask-Login
  - [X] Werkzeug
  - [X] python-dotenv
  - [ ] Pandas
  - [ ] scikit-learn
- [X] Create a `.env.example` file for configuration names.
- [ ] Separate configuration for development and production.
- [X] Add a Flask application factory.
- [ ] Create backend packages for routes, models, services, and utilities.
- [ ] Add a health-check route: `GET /api/health`.

## 2. Database: SQLite and SQLAlchemy

- [X] Configure SQLite through Flask-SQLAlchemy.
- [X] Create the database initialization workflow.
- [X] Create a `User` model:
  - [X] id
  - [X] name
  - [X] email
  - [X] password hash
  - [X] created timestamp
- [X] Create a `Scan` model:
  - [X] id
  - [X] user id
  - [X] scan type and input
  - [X] risk score
  - [X] classification
  - [X] reasons
  - [X] created timestamp
- [X] Create a `Feedback` model:
  - [X] id
  - [X] email
  - [X] message
  - [X] created timestamp
- [X] Add relationships and indexes.
- [X] Add migrations or a repeatable schema initialization command.
- [ ] Add seed data only for local development.

## 3. Authentication

- [X] Implement `POST /api/auth/signup`.
- [X] Validate name, email, password, and terms acceptance.
- [X] Reject duplicate email addresses.
- [X] Hash passwords with Werkzeug.
- [X] Implement `POST /api/auth/login`.
- [X] Verify credentials without exposing sensitive details.
- [X] Configure Flask-Login sessions.
- [X] Implement `POST /api/auth/logout`.
- [X] Add `GET /api/auth/me`.
- [X] Protect authenticated routes.
- [X] Add login, signup, logout, and invalid-input tests.
- [X] Add CSRF protection before production deployment.

## 4. URL input and rule-based detection

- [X] Add `POST /api/scans`.
- [X] Validate request JSON and URL format.
- [X] Normalize URLs before analysis.
- [X] Reject unsupported schemes and malformed input.
- [X] Add a rule engine for:
  - [X] Missing HTTPS
  - [X] Suspicious keywords
  - [X] Excessive URL length
  - [X] Excessive subdomains
  - [X] IP-address hosts
  - [X] Punycode or look-alike domains
  - [X] Suspicious redirects or query parameters
- [X] Produce a bounded risk score.
- [X] Return a classification such as Safe, Suspicious, or Dangerous.
- [X] Return human-readable reasons.
- [X] Store scan results for authenticated users.
- [X] Add endpoint rate limiting.
- [ ] Add request size limits.

### Message scanning

- [X] Validate and bound message input.
- [X] Detect urgency and coercive language.
- [X] Detect impersonation and authority claims.
- [X] Detect credential, OTP, and verification-code requests.
- [X] Detect payment and money-transfer requests.
- [X] Detect suspicious links and URL shorteners.
- [X] Return a bounded score, classification, and reasons.

## 5. Data processing with Pandas

- [X] Define the dataset schema and target label.
- [X] Add dataset loading and validation.
- [X] Handle missing, duplicate, and invalid rows.
- [X] Build URL feature extraction.
- [X] Split data into training and test sets.
- [X] Record dataset version and preprocessing decisions.
- [X] Prevent training/test data leakage.
- [X] Add repeatable preprocessing scripts.
- [X] Save processed datasets outside the web request path.

## 6. Machine-learning model with scikit-learn

- [X] Choose a baseline classifier.
- [X] Train a baseline model using extracted URL features.
- [X] Measure precision, recall, F1 score, and confusion matrix.
- [ ] Prioritize recall for dangerous URLs while monitoring false positives.
- [X] Save the trained model and feature metadata.
- [X] Add model loading at application startup.
- [X] Combine model output with rule-engine output.
- [X] Version model files.
- [X] Add a fallback when the model is unavailable.
- [ ] Never load untrusted serialized model files.
- [ ] Add prediction tests using known safe and suspicious examples.

## 7. Frontend-to-Flask integration

- [X] Connect signup form to `POST /api/auth/signup`.
- [X] Connect login form to `POST /api/auth/login`.
- [X] Connect logout controls.
- [ ] Add a scanner form to the homepage.
- [X] Send scanner requests with `fetch()`.
- [X] Display loading, success, validation, and server-error states.
- [X] Display risk score, classification, and reasons dynamically.
- [X] Connect feedback form to `POST /api/feedback`.
- [X] Handle expired sessions and unauthorized responses.
- [X] Avoid displaying raw server errors to users.

## 8. Analytics and Chart.js

- [X] Add an authenticated scan-history route.
- [X] Add aggregate risk statistics.
- [X] Add daily or weekly scan counts.
- [X] Add safe versus suspicious result counts.
- [X] Return chart-ready JSON.
- [ ] Render charts with Chart.js.
- [X] Restrict analytics to the current user or authorized administrators.
- [ ] Test empty-data and large-history cases.

## 9. Admin features

- [ ] Add an administrator role.
- [ ] Protect admin-only routes.
- [ ] Add scan and feedback summaries.
- [ ] Add user and scan filtering.
- [ ] Add pagination.
- [ ] Add safe export functionality.
- [ ] Audit sensitive admin actions.

## 10. Security and reliability

- [ ] Keep secrets and database paths out of source control.
- [ ] Validate and sanitize all external input.
- [ ] Use parameterized SQL through SQLAlchemy.
- [ ] Add secure session configuration.
- [ ] Add security headers.
- [ ] Configure production logging.
- [ ] Add consistent JSON error responses.
- [X] Add request timeouts and rate limits.
- [ ] Do not log passwords, tokens, or sensitive user data.
- [ ] Add dependency and vulnerability checks.

## 11. Testing

- [ ] Add Flask route tests.
- [ ] Add model and database tests.
- [ ] Add authentication tests.
- [ ] Add input-validation tests.
- [ ] Add rule-engine unit tests.
- [ ] Add ML feature and prediction tests.
- [ ] Add frontend integration tests for API responses.
- [ ] Test unauthorized and forbidden access.
- [ ] Test error handling and unavailable-model behavior.
- [ ] Run the complete test suite before deployment.

## 12. Deployment on Render

- [ ] Add a production WSGI server such as Gunicorn.
- [ ] Add a production start command.
- [ ] Configure environment variables in Render.
- [ ] Decide whether SQLite is sufficient for deployment persistence.
- [ ] Add a persistent disk or migrate to a managed database if required.
- [ ] Configure debug mode off.
- [ ] Configure allowed hosts and secure cookies.
- [ ] Add health checks.
- [ ] Run database initialization or migrations during deployment.
- [ ] Verify static files and API routes in production.
- [ ] Document rollback and backup procedures.

## Definition of done

- [ ] A user can create an account and log in securely.
- [ ] An authenticated user can submit a URL.
- [ ] Flask validates and analyzes the URL.
- [ ] Rule and ML results are combined into a risk response.
- [ ] The result is stored in SQLite through SQLAlchemy.
- [ ] The frontend displays the result dynamically.
- [X] Feedback is stored through a backend endpoint.
- [ ] Analytics are available through protected routes.
- [ ] Tests pass and production configuration is documented.
