from datetime import datetime, date, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def utc_now():
    return datetime.now(timezone.utc)

class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(80), nullable=False, default="General")
    due_date = db.Column(db.Date, nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    @property
    def is_overdue(self):
        if not self.is_completed and self.due_date:
            return self.due_date < date.today()
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "is_completed": self.is_completed,
            "is_overdue": self.is_overdue,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HabitLog(db.Model):
    __tablename__ = "habit_logs"

    id = db.Column(db.Integer, primary_key=True)
    log_date = db.Column(db.Date, nullable=False, unique=True, default=date.today)
    two_factor_auth = db.Column(db.Boolean, default=False)
    software_updates = db.Column(db.Boolean, default=False)
    avoid_pwd_reuse = db.Column(db.Boolean, default=False)
    phishing_vigilance = db.Column(db.Boolean, default=False)
    secure_wifi_vpn = db.Column(db.Boolean, default=False)
    screen_lock_backup = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    @property
    def score_percentage(self):
        habits = [
            self.two_factor_auth,
            self.software_updates,
            self.avoid_pwd_reuse,
            self.phishing_vigilance,
            self.secure_wifi_vpn,
            self.screen_lock_backup,
        ]
        completed = sum(1 for h in habits if h)
        return round((completed / len(habits)) * 100, 1)

    def to_dict(self):
        return {
            "id": self.id,
            "log_date": self.log_date.isoformat(),
            "two_factor_auth": self.two_factor_auth,
            "software_updates": self.software_updates,
            "avoid_pwd_reuse": self.avoid_pwd_reuse,
            "phishing_vigilance": self.phishing_vigilance,
            "secure_wifi_vpn": self.secure_wifi_vpn,
            "screen_lock_backup": self.screen_lock_backup,
            "notes": self.notes,
            "score_percentage": self.score_percentage,
        }


class PasswordEntry(db.Model):
    __tablename__ = "password_entries"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    service_for = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default="General")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "service_for": self.service_for,
            "username": self.username,
            "category": self.category,
            "notes": self.notes,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M"),
        }
