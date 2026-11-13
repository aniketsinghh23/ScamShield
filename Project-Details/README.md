
# 🛡️ ScamShield AI

### Intelligent Phishing & Online Scam Detection Platform

ScamShield AI is a web-based security project designed to help users identify potentially suspicious URLs and fraudulent online messages.

The goal is to develop an accessible platform that analyzes suspicious inputs, provides risk assessments, and helps users become more aware of online scams.

> 🚧 **Project Status:** Under Development

## 🎯 Problem Statement

Online scams, phishing websites, fake payment requests, and fraudulent messages are growing concerns in the digital world.

Many users struggle to distinguish legitimate websites and messages from suspicious ones.

ScamShield AI aims to address this problem through automated analysis and understandable security warnings.

## 💡 Project Objectives

- Analyze potentially suspicious URLs.
- Identify suspicious patterns in online messages.
- Generate risk scores and explanations.
- Maintain a history of submitted analyses.
- Provide an analytics dashboard.
- Help users make more informed online safety decisions.

## 🛠️ Technology Stack

| Technology   | Purpose                   |
| ------------ | ------------------------- |
| Python       | Backend programming       |
| Flask        | Web application framework |
| HTML5        | Webpage structure         |
| CSS3         | User interface styling    |
| JavaScript   | Frontend interactions     |
| SQLite       | Database                  |
| SQLAlchemy   | Database management       |
| Pandas       | Data processing           |
| Scikit-learn | Machine learning          |
| Git & GitHub | Version control           |

## 📂 Project Structure

```text
ScamShield-AI/
│
├── app.py
├── venv/
│
├── templates/
│   ├── index.html
│   └── about.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   │
│   └── js/
│       └── script.js
│
└── README.md
```

*The structure will expand as development progresses.*

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd ScamShield-AI
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

### 5. Install project dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure Google sign-in (optional)

Copy `.env.example` to `.env`, then create a Google OAuth web application in
Google Cloud Console. Add `http://127.0.0.1:5000/auth/google/callback` as an
authorized redirect URI and fill in `GOOGLE_CLIENT_ID` and
`GOOGLE_CLIENT_SECRET`. Keep `.env` private.

### 7. Run the application

```bash
python app.py
```

To rebuild the ML dataset from the two Kaggle sources and retrain the model:

```bash
python -m ml.build_balanced_dataset --rows-per-source 150
python -m ml.train_model
```

For production, use a WSGI server rather than Flask's development server.
Set `APP_ENV=production`, provide a Redis URL, set `FORCE_HTTPS=true`, and
start Gunicorn:

```bash
export APP_ENV=production
export RATELIMIT_STORAGE_URI=redis://localhost:6379/0
export FORCE_HTTPS=true
gunicorn --workers 2 --bind 0.0.0.0:8000 wsgi:app
```

On Windows PowerShell, use `$env:NAME=value` instead of `export NAME=value`.
Set a strong `SECRET_KEY`, a production database URL, and any OAuth secrets
through environment variables. Do not commit `.env` or production secrets.

Run the dependency audit separately:

```bash
pip-audit -r requirements.txt
```

Redis is used for shared rate-limit state in production. The default local
development configuration uses `memory://`; override
`RATELIMIT_STORAGE_URI` when using a hosted Redis instance.

### 8. Open in your browser

```text
http://127.0.0.1:5000/
```

## 🚀 Planned Features

- [X] Flask application setup
- [X] Basic homepage
- [X] About page
- [X] HTML and CSS integration
- [X] Basic JavaScript interactions
- [X] User authentication and password hashing
- [X] SQLite database setup with SQLAlchemy
- [X] Persistent scan records and per-user scan history
- [X] Protected scan analytics with daily and weekly chart data
- [X] Scanner API with risk scores, classifications, and reasons
- [X] Versioned URL dataset and scikit-learn baseline training pipeline
- [X] Kaggle popular-websites import for additional safe URL samples
- [X] Authenticated user dashboard
- [X] Realtime threat data dashboard with charts
- [ ] URL input validation
- [ ] Flask REST API integration
- [ ] SQLite database integration
- [ ] URL risk analysis engine
- [ ] Suspicious message analysis
- [ ] Machine learning integration
- [ ] Risk score visualization
- [ ] Analysis history
- [ ] Admin analytics dashboard
- [ ] Application deployment

## 📚 Learning Outcomes

Through this project, I aim to gain practical experience in:

- Python backend development
- Flask application architecture
- Frontend and backend integration
- REST API development
- Database operations and SQL
- Data preprocessing and machine learning
- Debugging and software testing
- Git and GitHub workflows
- Application deployment

## 🔒 Disclaimer

ScamShield AI is an educational and awareness-focused project. Its risk assessments are not a guarantee that a website or message is safe or fraudulent. Users should independently verify suspicious communications and avoid sharing sensitive information.

## 👨‍💻 Developer

**Aniket Singh**

B.Tech Computer Science Engineering Student

GitHub: [aniketsinghh23](https://github.com/aniketsinghh23)

---

⭐ If you find this project interesting, feel free to explore the repository and follow its development.

**Built with Python, curiosity, and a passion for learning.**
