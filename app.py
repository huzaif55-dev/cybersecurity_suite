from datetime import date, datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from config import Config
from models import db, Task, HabitLog, PasswordEntry
from services.checklist_service import (
    seed_default_tasks,
    add_task,
    toggle_task,
    delete_task,
    get_tasks,
    get_checklist_stats,
)
from services.link_checker import analyze_message_and_link
from services.habit_service import (
    seed_sample_habits_if_empty,
    record_daily_habits,
    get_weekly_progress,
    HABIT_DEFINITIONS,
)
from services.ml_classifier import classifier_manager
from services.password_service import (
    seed_sample_passwords_if_empty,
    get_all_passwords,
    save_password_entry,
    update_password_entry,
    delete_password_entry,
    suggest_passwords_from_input,
    generate_strong_password,
    analyze_password,
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_default_tasks()
        seed_sample_habits_if_empty()
        seed_sample_passwords_if_empty()

    # ------------------ Routes ------------------

    @app.route("/")
    def index():
        checklist_stats = get_checklist_stats()
        weekly_habits = get_weekly_progress()
        vault_entries = get_all_passwords()

        # Check if ML classifier is loaded
        ml_trained = classifier_manager.is_trained

        return render_template(
            "index.html",
            checklist_stats=checklist_stats,
            weekly_habits=weekly_habits,
            vault_count=len(vault_entries),
            ml_trained=ml_trained,
        )

    # 1. Security Checklist
    @app.route("/checklist")
    def checklist():
        filter_by = request.args.get("filter", "all")
        tasks = get_tasks(filter_by)
        stats = get_checklist_stats()
        today = date.today().isoformat()
        return render_template(
            "checklist.html",
            tasks=tasks,
            stats=stats,
            filter_by=filter_by,
            today=today,
        )

    @app.route("/checklist/add", methods=["POST"])
    def checklist_add():
        title = request.form.get("title")
        category = request.form.get("category", "General")
        due_date = request.form.get("due_date")
        description = request.form.get("description", "")

        if title and due_date:
            add_task(title, category, due_date, description)
            flash("Security task added successfully!", "success")
        else:
            flash("Please provide both a task title and due date.", "danger")
        return redirect(url_for("checklist"))

    @app.route("/checklist/toggle/<int:task_id>", methods=["POST"])
    def checklist_toggle(task_id):
        toggle_task(task_id)
        return redirect(request.referrer or url_for("checklist"))

    @app.route("/checklist/delete/<int:task_id>", methods=["POST"])
    def checklist_delete(task_id):
        delete_task(task_id)
        flash("Task removed from checklist.", "info")
        return redirect(request.referrer or url_for("checklist"))

    @app.route("/checklist/seed-templates", methods=["POST"])
    def checklist_seed():
        seed_default_tasks()
        flash("Default security review tasks refreshed.", "success")
        return redirect(url_for("checklist"))

    # 2. Suspicious Message & Link Checker
    @app.route("/link-checker", methods=["GET", "POST"])
    def link_checker():
        result = None
        input_text = ""
        input_url = ""

        if request.method == "POST":
            input_text = request.form.get("message_text", "")
            input_url = request.form.get("target_url", "")
            if input_text or input_url:
                result = analyze_message_and_link(input_text, input_url)
            else:
                flash("Please enter a message or a URL to analyze.", "warning")

        return render_template(
            "link_checker.html",
            result=result,
            input_text=input_text,
            input_url=input_url,
        )

    # 3. Security Habit Tracker
    @app.route("/habits")
    def habits():
        progress = get_weekly_progress()
        today_iso = date.today().isoformat()
        return render_template(
            "habits.html",
            progress=progress,
            habit_definitions=HABIT_DEFINITIONS,
            today_iso=today_iso,
        )

    @app.route("/habits/log", methods=["POST"])
    def habits_log():
        log_date_str = request.form.get("log_date")
        try:
            log_date = datetime.strptime(log_date_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            log_date = date.today()

        tfa = "two_factor_auth" in request.form
        updates = "software_updates" in request.form
        pwd_reuse = "avoid_pwd_reuse" in request.form
        phishing = "phishing_vigilance" in request.form
        wifi_vpn = "secure_wifi_vpn" in request.form
        screen_lock = "screen_lock_backup" in request.form
        notes = request.form.get("notes", "")

        record_daily_habits(log_date, tfa, updates, pwd_reuse, phishing, wifi_vpn, screen_lock, notes)
        flash(f"Security habits for {log_date.strftime('%B %d, %Y')} recorded successfully!", "success")
        return redirect(url_for("habits"))

    # 4. ML Scam Message Classifier
    @app.route("/ml-classifier", methods=["GET", "POST"])
    def ml_classifier():
        # Ensure model is initialized
        if not classifier_manager.is_trained:
            classifier_manager.load_or_train()

        classification = None
        test_message = ""

        if request.method == "POST" and "classify_btn" in request.form:
            test_message = request.form.get("message_text", "").strip()
            if test_message:
                classification = classifier_manager.classify(test_message)
            else:
                flash("Please enter an SMS or message to test.", "warning")

        return render_template(
            "ml_classifier.html",
            metrics=classifier_manager.metrics,
            dataset_info=classifier_manager.dataset_info,
            classification=classification,
            test_message=test_message,
        )

    @app.route("/ml-classifier/retrain", methods=["POST"])
    def ml_retrain():
        try:
            classifier_manager.train()
            flash("Model successfully retrained on the UCI SMS Spam dataset!", "success")
        except Exception as e:
            flash(f"Error training model: {str(e)}", "danger")
        return redirect(url_for("ml_classifier"))

    # 5. Password Manager & Analyzer
    @app.route("/passwords")
    def password_manager():
        passwords = get_all_passwords()
        return render_template("password_manager.html", passwords=passwords)

    @app.route("/passwords/save", methods=["POST"])
    def passwords_save():
        name = request.form.get("name")
        service_for = request.form.get("service_for")
        username = request.form.get("username", "")
        plain_password = request.form.get("password")
        category = request.form.get("category", "General")
        notes = request.form.get("notes", "")

        if name and service_for and plain_password:
            save_password_entry(name, service_for, username, plain_password, category, notes)
            flash(f"Password for '{service_for}' encrypted and saved with current date!", "success")
        else:
            flash("Name, service for, and password are required.", "danger")
        return redirect(url_for("password_manager"))

    @app.route("/passwords/update/<int:entry_id>", methods=["POST"])
    def passwords_update(entry_id):
        name = request.form.get("name")
        service_for = request.form.get("service_for")
        username = request.form.get("username", "")
        plain_password = request.form.get("password")
        category = request.form.get("category", "General")
        notes = request.form.get("notes", "")

        if name and service_for:
            update_password_entry(entry_id, name, service_for, username, plain_password, category, notes)
            flash(f"Password entry '{service_for}' updated.", "success")
        return redirect(url_for("password_manager"))

    @app.route("/passwords/delete/<int:entry_id>", methods=["POST"])
    def passwords_delete(entry_id):
        delete_password_entry(entry_id)
        flash("Password entry removed from vault.", "info")
        return redirect(url_for("password_manager"))

    # JSON APIs for interactive AJAX features
    @app.route("/api/passwords/suggest", methods=["POST"])
    def api_suggest_passwords():
        data = request.get_json() or {}
        base_input = data.get("input", "")
        suggestions = suggest_passwords_from_input(base_input)
        return jsonify({"status": "success", "suggestions": suggestions})

    @app.route("/api/passwords/generate", methods=["POST"])
    def api_generate_password():
        data = request.get_json() or {}
        length = int(data.get("length", 16))
        use_upper = bool(data.get("use_upper", True))
        use_lower = bool(data.get("use_lower", True))
        use_digits = bool(data.get("use_digits", True))
        use_symbols = bool(data.get("use_symbols", True))

        pwd = generate_strong_password(length, use_upper, use_lower, use_digits, use_symbols)
        analysis = analyze_password(pwd)
        return jsonify({"password": pwd, "analysis": analysis})

    @app.route("/api/passwords/analyze", methods=["POST"])
    def api_analyze_password():
        data = request.get_json() or {}
        pwd = data.get("password", "")
        analysis = analyze_password(pwd)
        return jsonify(analysis)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
