from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    google_id = db.Column(db.String(255), unique=True, nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    scans = db.relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    feedback = db.relationship("Feedback", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
        }


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        db.Index("ix_scans_user_created_at", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_type = db.Column(db.String(20), nullable=False)
    input_text = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    classification = db.Column(db.String(20), nullable=False)
    reasons = db.Column(db.Text, nullable=False)
    model_label = db.Column(db.String(20), nullable=True)
    model_confidence = db.Column(db.Float, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="scans")

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.scan_type,
            "input": self.input_text,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "reasons": self.reasons.split("\n") if self.reasons else [],
            "model_prediction": self.model_label,
            "model_confidence": self.model_confidence,
            "created_at": self.created_at.isoformat(),
        }


class Feedback(db.Model):
    __tablename__ = "feedback"
    __table_args__ = (
        db.Index("ix_feedback_user_created_at", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="feedback")