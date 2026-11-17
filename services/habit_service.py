from datetime import date, timedelta
from models import db, HabitLog

HABIT_DEFINITIONS = [
    {
        "id": "two_factor_auth",
        "name": "2FA / MFA Usage",
        "desc": "Used two-factor authentication (authenticator app or hardware key) for logins.",
        "icon": "bi-shield-lock-fill",
    },
    {
        "id": "software_updates",
        "name": "Software & OS Updates",
        "desc": "Checked or installed security updates for OS, browsers, and applications.",
        "icon": "bi-arrow-repeat",
    },
    {
        "id": "avoid_pwd_reuse",
        "name": "Avoid Password Reuse",
        "desc": "Generated unique passwords for each service without reusing credentials.",
        "icon": "bi-key-fill",
    },
    {
        "id": "phishing_vigilance",
        "name": "Phishing & Link Inspection",
        "desc": "Carefully verified unexpected messages, senders, and links before clicking.",
        "icon": "bi-envelope-exclamation-fill",
    },
    {
        "id": "secure_wifi_vpn",
        "name": "Secure Network & VPN",
        "desc": "Avoided unencrypted public Wi-Fi or used a trusted VPN.",
        "icon": "bi-wifi",
    },
    {
        "id": "screen_lock_backup",
        "name": "Screen Lock & Backups",
        "desc": "Locked screens when away from devices and verified critical file backups.",
        "icon": "bi-laptop",
    },
]

def seed_sample_habits_if_empty():
    if HabitLog.query.count() == 0:
        today = date.today()
        # Create a week's worth of realistic sample habits
        sample_data = [
            (6, True, True, True, True, True, True),
            (5, True, False, True, True, False, True),
            (4, True, True, True, True, True, False),
            (3, False, True, True, False, True, True),
            (2, True, True, True, True, True, True),
            (1, True, False, True, True, False, True),
        ]
        for days_ago, tfa, updates, pwd, phish, vpn, lock in sample_data:
            entry_date = today - timedelta(days=days_ago)
            log = HabitLog(
                log_date=entry_date,
                two_factor_auth=tfa,
                software_updates=updates,
                avoid_pwd_reuse=pwd,
                phishing_vigilance=phish,
                secure_wifi_vpn=vpn,
                screen_lock_backup=lock,
                notes="Automated security habit baseline check.",
            )
            db.session.add(log)
        db.session.commit()

def record_daily_habits(log_date, two_factor, updates, pwd_reuse, phishing, wifi_vpn, screen_lock, notes=""):
    existing = HabitLog.query.filter_by(log_date=log_date).first()
    if existing:
        existing.two_factor_auth = bool(two_factor)
        existing.software_updates = bool(updates)
        existing.avoid_pwd_reuse = bool(pwd_reuse)
        existing.phishing_vigilance = bool(phishing)
        existing.secure_wifi_vpn = bool(wifi_vpn)
        existing.screen_lock_backup = bool(screen_lock)
        existing.notes = notes
        db.session.commit()
        return existing

    new_log = HabitLog(
        log_date=log_date,
        two_factor_auth=bool(two_factor),
        software_updates=bool(updates),
        avoid_pwd_reuse=bool(pwd_reuse),
        phishing_vigilance=bool(phishing),
        secure_wifi_vpn=bool(wifi_vpn),
        screen_lock_backup=bool(screen_lock),
        notes=notes,
    )
    db.session.add(new_log)
    db.session.commit()
    return new_log

def get_weekly_progress():
    today = date.today()
    start_date = today - timedelta(days=6)

    # Fetch last 7 days records
    logs = HabitLog.query.filter(HabitLog.log_date >= start_date, HabitLog.log_date <= today).order_by(HabitLog.log_date.asc()).all()
    logs_by_date = {log.log_date: log for log in logs}

    labels = []
    daily_scores = []
    habit_counts = {
        "two_factor_auth": 0,
        "software_updates": 0,
        "avoid_pwd_reuse": 0,
        "phishing_vigilance": 0,
        "secure_wifi_vpn": 0,
        "screen_lock_backup": 0,
    }

    for i in range(7):
        current_day = start_date + timedelta(days=i)
        day_str = current_day.strftime("%a (%b %d)")
        labels.append(day_str)

        if current_day in logs_by_date:
            log = logs_by_date[current_day]
            daily_scores.append(log.score_percentage)
            if log.two_factor_auth: habit_counts["two_factor_auth"] += 1
            if log.software_updates: habit_counts["software_updates"] += 1
            if log.avoid_pwd_reuse: habit_counts["avoid_pwd_reuse"] += 1
            if log.phishing_vigilance: habit_counts["phishing_vigilance"] += 1
            if log.secure_wifi_vpn: habit_counts["secure_wifi_vpn"] += 1
            if log.screen_lock_backup: habit_counts["screen_lock_backup"] += 1
        else:
            daily_scores.append(0)

    logged_days_count = len(logs)
    avg_score = round(sum(daily_scores) / 7.0, 1)

    # Habit completion percentages out of 7 days
    habit_breakdown = []
    for h in HABIT_DEFINITIONS:
        count = habit_counts[h["id"]]
        rate = round((count / 7.0) * 100, 1)
        habit_breakdown.append({
            "id": h["id"],
            "name": h["name"],
            "icon": h["icon"],
            "completed_days": count,
            "rate": rate,
        })

    # Calculate Current Streak
    streak = 0
    check_day = today
    while True:
        entry = HabitLog.query.filter_by(log_date=check_day).first()
        if entry and entry.score_percentage >= 50:
            streak += 1
            check_day = check_day - timedelta(days=1)
        else:
            break

    # Security Recommendations based on weaknesses
    recommendations = []
    weak_habits = sorted(habit_breakdown, key=lambda x: x["rate"])
    for h in weak_habits[:3]:
        if h["rate"] < 70:
            if h["id"] == "two_factor_auth":
                recommendations.append("Priority: Enable hardware security keys (FIDO2/YubiKey) or TOTP apps for Google, Apple, and financial accounts.")
            elif h["id"] == "software_updates":
                recommendations.append("Priority: Turn on automatic updates for Windows/macOS and web browsers to patch zero-day vulnerabilities.")
            elif h["id"] == "avoid_pwd_reuse":
                recommendations.append("Priority: Use the Password Manager to replace recycled passwords with high-entropy unique strings.")
            elif h["id"] == "phishing_vigilance":
                recommendations.append("Priority: Cross-reference unexpected emails with the Suspicious Message & Link Checker before opening.")
            elif h["id"] == "secure_wifi_vpn":
                recommendations.append("Priority: Activate a reputable encrypted VPN when connecting to airport, cafe, or hotel Wi-Fi.")
            elif h["id"] == "screen_lock_backup":
                recommendations.append("Priority: Set screen timeout to 2-3 minutes and configure automated nightly cloud/external drive backups.")

    if not recommendations:
        recommendations.append("Outstanding work! Your security habits are consistently strong across all tracked areas.")
        recommendations.append("Maintain your momentum by conducting quarterly security reviews and testing offline disaster recovery backups.")

    return {
        "labels": labels,
        "daily_scores": daily_scores,
        "avg_score": avg_score,
        "logged_days_count": logged_days_count,
        "habit_breakdown": habit_breakdown,
        "streak": streak,
        "recommendations": recommendations,
        "today_log": HabitLog.query.filter_by(log_date=today).first(),
    }
