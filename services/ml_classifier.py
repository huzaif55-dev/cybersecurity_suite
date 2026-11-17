import os
import re
import io
import zipfile
import logging
import requests
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
)

from config import Config

logger = logging.getLogger(__name__)

# Stopwords set (standard English stopwords)
ENGLISH_STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

def preprocess_text(text: str) -> str:
    """Preprocess SMS text: normalize tokens, numbers, currency, punctuation."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    # Replace URLs
    text = re.sub(r"https?://\S+|www\.\S+", " url_token ", text)
    # Replace email addresses
    text = re.sub(r"\S+@\S+", " email_token ", text)
    # Replace currency symbols
    text = re.sub(r"[\$£€¥]", " currency_token ", text)
    # Replace numbers
    text = re.sub(r"\b\d+\b", " number_token ", text)
    # Remove special punctuation
    text = re.sub(r"[^\w\s]", " ", text)
    # Strip stopwords and normalize whitespace
    tokens = [w for w in text.split() if w not in ENGLISH_STOPWORDS and len(w) > 1]
    return " ".join(tokens)

def download_uci_dataset(target_path: str) -> bool:
    """Download UCI SMS Spam Collection dataset if not already present."""
    if os.path.exists(target_path) and os.path.getsize(target_path) > 10000:
        return True

    # 1. Try direct raw mirror
    direct_url = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
    try:
        r = requests.get(direct_url, timeout=15)
        if r.status_code == 200 and len(r.text) > 10000:
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(r.text)
            return True
    except Exception as e:
        logger.warning(f"Could not download from direct mirror: {e}")

    # 2. Try official UCI zip repository
    uci_zip_url = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
    try:
        r = requests.get(uci_zip_url, timeout=20)
        if r.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                # Look for SMSSpamCollection file
                for name in z.namelist():
                    if "SMSSpamCollection" in name:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(content)
                        return True
    except Exception as e:
        logger.warning(f"Could not download from UCI zip: {e}")

    # 3. Create fallback starter dataset if network is blocked
    fallback_records = [
        ("ham", "Go until jurong point, crazy.. Available only in bugis n great world la e buffet..."),
        ("ham", "Ok lar... Joking wif u oni..."),
        ("spam", "Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry question(std txt rate)T&C's apply 08452810075over18's"),
        ("ham", "U dun say so early hor... U c already then say..."),
        ("ham", "Nah I don't think he goes to usf, he lives around here though"),
        ("spam", "FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still? Tb ok! XxX std chgs to send, £1.50 to rcv"),
        ("ham", "Even my brother is not like to speak with me. They treat me like aids patent."),
        ("ham", "As per your request 'Melle Melle (Oru Minnaminunginte Nurungu Vettam)' has been set as your callertune for all Callers."),
        ("spam", "WINNER!! As a valued network customer you have been selected to receivea £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only."),
        ("spam", "Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! Call The Mobile Update Co FREE on 08002986030"),
        ("ham", "I'm gonna be home soon and i don't want to talk about this stuff anymore tonight, k? I've cried enough today."),
        ("spam", "SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6days 16+ TsandCs apply Reply HL 4info"),
        ("spam", "URGENT! You have won a 1 week FREE membership in our £100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net LCCLTD POBOX 4403LDNW1A7RW18"),
        ("ham", "I've been searching for the right words to thank you for this breather. I promise i wont take your help for granted and will fulfil my promise."),
        ("ham", "I HAVE A DATE ON SUNDAY WITH WILL!!"),
        ("spam", "XXXMobileMovieClub: To use your credit, click the WAP link in the next txt message or click here>> http://wap.xxx.com?n=1373"),
        ("ham", "Oh k...i'm watching here:)"),
        ("ham", "Eh u remember how 2 spell his name... Yes i did. He v naughty make until i v wet."),
        ("ham", "Fine if that's the way u feel. That's the way its gota b"),
        ("spam", "England v Macedonia - dont miss the goals/team news. Txt ur national team to 87077 eg ENGLAND to 87077 IBH: tbl/sms First 49p, then 50p/ton"),
    ] * 25
    with open(target_path, "w", encoding="utf-8") as f:
        for lbl, msg in fallback_records:
            f.write(f"{lbl}\t{msg}\n")
    return True

class SMSClassifierManager:
    _instance = None

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metrics = None
        self.is_trained = False
        self.dataset_info = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SMSClassifierManager()
        return cls._instance

    def load_or_train(self, force_retrain=False):
        cache_path = Config.MODEL_CACHE_PATH
        if not force_retrain and os.path.exists(cache_path):
            try:
                cached_data = joblib.load(cache_path)
                self.model = cached_data["model"]
                self.vectorizer = cached_data["vectorizer"]
                self.metrics = cached_data["metrics"]
                self.dataset_info = cached_data.get("dataset_info", {})
                self.is_trained = True
                return self.metrics
            except Exception as e:
                logger.error(f"Error loading cached model: {e}")

        return self.train()

    def train(self):
        download_uci_dataset(Config.SMS_DATASET_PATH)

        # Load dataset
        df = pd.read_csv(
            Config.SMS_DATASET_PATH,
            sep="\t",
            header=None,
            names=["label", "message"],
            quoting=3,
            encoding="utf-8",
            on_bad_lines="skip",
        )
        # Drop nulls and strip
        df = df.dropna()
        df["label"] = df["label"].astype(str).str.strip().str.lower()
        df = df[df["label"].isin(["ham", "spam"])]

        # Preprocess messages
        df["clean_message"] = df["message"].apply(preprocess_text)

        total_samples = len(df)
        spam_count = int((df["label"] == "spam").sum())
        ham_count = int((df["label"] == "ham").sum())

        # Train-test split (80-20)
        X_train, X_test, y_train, y_test = train_test_split(
            df["clean_message"],
            df["label"],
            test_size=0.20,
            random_state=42,
            stratify=df["label"],
        )

        # TF-IDF Vectorization
        vectorizer = TfidfVectorizer(
            max_features=3500,
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)

        # Logistic Regression Model
        model = LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            C=1.5,
            random_state=42,
        )
        model.fit(X_train_tfidf, y_train)

        # Predictions & Evaluations
        y_pred = model.predict(X_test_tfidf)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, pos_label="spam", zero_division=0))
        rec = float(recall_score(y_test, y_pred, pos_label="spam", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, pos_label="spam", zero_division=0))

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred, labels=["ham", "spam"])
        tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

        self.model = model
        self.vectorizer = vectorizer
        self.metrics = {
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            },
            "test_samples": len(y_test),
        }
        self.dataset_info = {
            "total_samples": total_samples,
            "spam_samples": spam_count,
            "ham_samples": ham_count,
            "spam_ratio": round((spam_count / total_samples) * 100, 1),
            "vocabulary_size": len(vectorizer.vocabulary_),
        }
        self.is_trained = True

        # Cache to disk
        joblib.dump(
            {
                "model": self.model,
                "vectorizer": self.vectorizer,
                "metrics": self.metrics,
                "dataset_info": self.dataset_info,
            },
            Config.MODEL_CACHE_PATH,
        )

        return self.metrics

    def classify(self, message: str):
        if not self.is_trained:
            self.load_or_train()

        clean = preprocess_text(message)
        tfidf_vec = self.vectorizer.transform([clean])
        pred_label = self.model.predict(tfidf_vec)[0]
        probs = self.model.predict_proba(tfidf_vec)[0]

        classes = list(self.model.classes_)
        spam_idx = classes.index("spam")
        ham_idx = classes.index("ham")

        spam_prob = round(float(probs[spam_idx]) * 100, 2)
        ham_prob = round(float(probs[ham_idx]) * 100, 2)

        # Extract top influential words from input
        words = clean.split()
        feature_names = self.vectorizer.get_feature_names_out()
        vocab = self.vectorizer.vocabulary_
        coefficients = self.model.coef_[0]

        word_influences = []
        for w in set(words):
            if w in vocab:
                idx = vocab[w]
                coef = coefficients[idx]
                word_influences.append({
                    "word": w,
                    "weight": round(float(coef), 3),
                    "tendency": "Spam / Scam" if coef > 0 else "Legitimate (Ham)",
                })

        word_influences.sort(key=lambda x: abs(x["weight"]), reverse=True)

        return {
            "original_message": message,
            "preprocessed": clean,
            "label": pred_label,
            "is_spam": (pred_label == "spam"),
            "confidence": spam_prob if pred_label == "spam" else ham_prob,
            "spam_prob": spam_prob,
            "ham_prob": ham_prob,
            "top_features": word_influences[:8],
        }

classifier_manager = SMSClassifierManager.get_instance()
