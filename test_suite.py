import unittest
from datetime import date, timedelta
from app import create_app
from models import db, Task, HabitLog, PasswordEntry
from services.link_checker import analyze_message_and_link
from services.ml_classifier import classifier_manager
from services.password_service import (
    suggest_passwords_from_input,
    analyze_password,
    encrypt_password,
    decrypt_password,
)
from services.habit_service import get_weekly_progress
from services.checklist_service import get_checklist_stats

class CyberShieldTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def test_01_checklist(self):
        """Test Feature 1: Security Checklist"""
        with self.app.app_context():
            stats = get_checklist_stats()
            self.assertGreater(stats["total"], 0)
            self.assertIn("completion_rate", stats)

        response = self.client.get("/checklist")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Checklist", response.data)

        # Test adding a task
        response = self.client.post("/checklist/add", data={
            "title": "Unit Test Backup Task",
            "category": "Backups",
            "due_date": (date.today() + timedelta(days=5)).isoformat(),
            "description": "Test backup task description",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unit Test Backup Task", response.data)

    def test_02_link_checker(self):
        """Test Feature 2: Suspicious Message & Link Checker"""
        # Test dangerous phishing input
        result = analyze_message_and_link(
            text="URGENT: Your Bank of America account is suspended! Confirm your password now.",
            explicit_url="http://192.168.1.100/login.php"
        )
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn(result["verdict_class"], ["danger", "warning"])
        self.assertGreater(result["total_flags"], 0)
        self.assertGreater(len(result["recommendations"]), 0)

        # Test web endpoint
        response = self.client.post("/link-checker", data={
            "message_text": "Claim your $5000 lottery cash prize immediately at http://bit.ly/claim",
            "target_url": ""
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Why Something Was Flagged", response.data)

    def test_03_habit_tracker(self):
        """Test Feature 3: Security Habit Tracker"""
        with self.app.app_context():
            progress = get_weekly_progress()
            self.assertEqual(len(progress["labels"]), 7)
            self.assertEqual(len(progress["daily_scores"]), 7)
            self.assertGreater(len(progress["habit_breakdown"]), 0)

        response = self.client.get("/habits")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Habit Tracker", response.data)

        # Test daily log
        response = self.client.post("/habits/log", data={
            "log_date": date.today().isoformat(),
            "two_factor_auth": "1",
            "software_updates": "1",
            "avoid_pwd_reuse": "1",
            "phishing_vigilance": "1",
            "secure_wifi_vpn": "1",
            "screen_lock_backup": "1",
            "notes": "Testing habit tracker check-in",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"recorded successfully", response.data)

    def test_04_ml_scam_classifier(self):
        """Test Feature 4: ML Scam Message Classifier"""
        # Train / load model
        metrics = classifier_manager.load_or_train()
        self.assertIn("accuracy", metrics)
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1_score", metrics)
        self.assertIn("confusion_matrix", metrics)

        # Test classification inference
        spam_test = classifier_manager.classify("WINNER! You have won a £1000 prize reward. Call 09061701461 to claim now!")
        self.assertEqual(spam_test["label"], "spam")
        self.assertTrue(spam_test["is_spam"])
        self.assertGreater(spam_test["spam_prob"], 50)

        ham_test = classifier_manager.classify("Hey, are we still meeting tomorrow for coffee around noon?")
        self.assertEqual(ham_test["label"], "ham")
        self.assertFalse(ham_test["is_spam"])

        response = self.client.get("/ml-classifier")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Confusion Matrix", response.data)

    def test_05_password_manager_and_analyzer(self):
        """Test Feature 5: Password Manager & Analyzer"""
        # Test input-based suggestions
        suggestions = suggest_passwords_from_input("MySecretKey")
        self.assertEqual(len(suggestions), 3)
        for s in suggestions:
            self.assertIn("password", s)
            self.assertIn("analysis", s)
            self.assertGreater(s["analysis"]["score"], 40)

        # Test AES encryption/decryption
        secret = "Ultra$ecureP@ss2026!"
        encrypted = encrypt_password(secret)
        self.assertNotEqual(secret, encrypted)
        decrypted = decrypt_password(encrypted)
        self.assertEqual(secret, decrypted)

        # Test analyzer
        analysis = analyze_password("Weak123")
        self.assertIn(analysis["strength"], ["Weak", "Very Weak"])
        strong_analysis = analyze_password("X#9vL2@qR8*zT1!98Wq")
        self.assertIn(strong_analysis["strength"], ["Strong", "Very Strong"])

        # Test web endpoint
        response = self.client.get("/passwords")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password Manager", response.data)

        # Test saving password with name and for and date
        response = self.client.post("/passwords/save", data={
            "name": "Integration Vault Key",
            "service_for": "gitlab.com",
            "username": "tester@test.com",
            "password": "G!tl@b_Sup3r$ecure2026",
            "category": "Development",
            "notes": "Test notes",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"gitlab.com", response.data)

if __name__ == "__main__":
    unittest.main()
