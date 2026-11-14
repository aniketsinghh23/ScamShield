# ScamShield AI

ScamShield AI analyzes suspicious URLs and messages, explains potential risks,
and keeps scan history for authenticated users.

## Features

- URL and message scam detection with risk scores and explanations
- User authentication with email/password and optional Google sign-in
- Private scan history and dashboard analytics
- Baseline machine-learning URL classifier
- Realtime threat information dashboard

## Technology

- Python and Flask
- Flask-SQLAlchemy with SQLite
- Flask-Login and Authlib
- JavaScript, HTML, and CSS
- Pandas, scikit-learn, and joblib

## Setup

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure environment variables

Copy `.env.example` to `.env` and set private values:

```env
SECRET_KEY=replace-with-a-long-random-value
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
```

For Google sign-in, create a Web application OAuth client in Google Cloud
Console and add this authorized redirect URI:

```text
http://127.0.0.1:5000/auth/google/callback
```

Keep `.env` and downloaded Google credential JSON files private. They are
excluded by `.gitignore`.

### 4. Run locally

```powershell
python app.py
```

Open <http://127.0.0.1:5000/>.

## Machine-learning commands

Rebuild the balanced dataset and train the URL model:

```powershell
python -m ml.build_balanced_dataset --rows-per-source 150
python -m ml.train_model
```

## Testing

```powershell
python -m pytest -q
```

## Production

For production, set `APP_ENV=production`, configure a production database and
Redis URL, enable `FORCE_HTTPS=true`, set a strong `SECRET_KEY`, and run with
a WSGI server such as Gunicorn:

```bash
gunicorn --workers 2 --bind 0.0.0.0:8000 wsgi:app
```

## Disclaimer

ScamShield AI is an educational security tool. Its results are not a guarantee
that a website or message is safe or fraudulent. Independently verify
suspicious communications and avoid sharing sensitive information.
