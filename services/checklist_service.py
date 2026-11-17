from datetime import datetime, date, timedelta, timezone
from models import db, Task

DEFAULT_SECURITY_TEMPLATES = [
    {
        "title": "Apply Operating System & Security Patches",
        "category": "Software Updates",
        "description": "Ensure Windows/macOS/Linux and all installed browsers and core software are patched to latest versions.",
        "due_offset_days": 2,
    },
    {
        "title": "Perform Full Offsite / Cloud Backup",
        "category": "Backups",
        "description": "Backup essential documents, code repositories, and configuration files using the 3-2-1 backup strategy.",
        "due_offset_days": 4,
    },
    {
        "title": "Audit Two-Factor Authentication (2FA) on Critical Accounts",
        "category": "Security Reviews",
        "description": "Verify that email, banking, GitHub, and cloud provider accounts have TOTP/Security Key 2FA enabled.",
        "due_offset_days": 7,
    },
    {
        "title": "Review Wi-Fi Router Security & Firmware",
        "category": "Security Reviews",
        "description": "Disable WPS, update router firmware, change default admin credentials, and enable WPA3/WPA2-AES encryption.",
        "due_offset_days": 10,
    },
    {
        "title": "Audit Password Hygiene & Revoke Inactive Sessions",
        "category": "Security Reviews",
        "description": "Scan for duplicated or leaked passwords, change weak credentials, and terminate obsolete active sessions.",
        "due_offset_days": 14,
    },
]

def seed_default_tasks():
    if Task.query.count() == 0:
        today = date.today()
        for t in DEFAULT_SECURITY_TEMPLATES:
            task = Task(
                title=t["title"],
                category=t["category"],
                description=t["description"],
                due_date=today + timedelta(days=t["due_offset_days"]),
                is_completed=False,
            )
            db.session.add(task)
        db.session.commit()

def add_task(title, category, due_date_str, description=""):
    try:
        due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        due_date = date.today() + timedelta(days=7)

    task = Task(
        title=title.strip(),
        category=category.strip() if category else "General",
        due_date=due_date,
        description=description.strip() if description else "",
        is_completed=False,
    )
    db.session.add(task)
    db.session.commit()
    return task

def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    task.is_completed = not task.is_completed
    task.completed_at = datetime.now(timezone.utc) if task.is_completed else None
    db.session.commit()
    return task

def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    return True

def get_tasks(filter_by="all"):
    today = date.today()
    query = Task.query

    if filter_by == "pending":
        query = query.filter(Task.is_completed == False, Task.due_date >= today)
    elif filter_by == "completed":
        query = query.filter(Task.is_completed == True)
    elif filter_by == "overdue":
        query = query.filter(Task.is_completed == False, Task.due_date < today)

    tasks = query.order_by(Task.due_date.asc(), Task.id.desc()).all()
    return tasks

def get_checklist_stats():
    today = date.today()
    all_tasks = Task.query.all()
    total = len(all_tasks)
    completed = sum(1 for t in all_tasks if t.is_completed)
    overdue = sum(1 for t in all_tasks if not t.is_completed and t.due_date < today)
    pending = total - completed - overdue
    completion_rate = round((completed / total) * 100, 1) if total > 0 else 0.0

    return {
        "total": total,
        "completed": completed,
        "overdue": overdue,
        "pending": pending,
        "completion_rate": completion_rate,
    }
