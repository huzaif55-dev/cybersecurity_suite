import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cyber-shield-super-secret-key-2026")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'cyber_shield.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATA_DIR = DATA_DIR
    SMS_DATASET_PATH = os.path.join(DATA_DIR, "sms_spam.tsv")
    MODEL_CACHE_PATH = os.path.join(DATA_DIR, "sms_classifier_model.joblib")
    VAULT_KEY_PATH = os.path.join(DATA_DIR, "vault.key")
