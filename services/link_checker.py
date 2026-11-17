import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "Urgency & Threat Tactics": [
        (r"\b(urgent|immediately|act now|immediate action|critical alert)\b", "High urgency pressure to make you act without thinking.", "warning", 15),
        (r"\b(account suspended|account locked|access terminated|deactivated|disabled)\b", "Claims account suspension to induce panic.", "danger", 25),
        (r"\b(unauthorized access|suspicious activity|security breach|compromised)\b", "False security alert tactic used in spear phishing.", "warning", 20),
        (r"\b(arrest warrant|law enforcement|fbi|irs|police|legal action|court summons)\b", "Impersonation of legal authority to intimidate victims.", "danger", 30),
    ],
    "Financial & Prize Bait": [
        (r"\b(you have won|lottery winner|cash prize|claim reward|sweepstakes)\b", "Classic advance-fee fraud / prize bait scam.", "danger", 25),
        (r"\b(bitcoin|crypto(currency)?|wallet payout|guaranteed returns|invest \$?\d+)\b", "High-risk cryptocurrency or investment scam trigger.", "danger", 25),
        (r"\b(tax refund|irs refund|government stimulus|unclaimed funds|wire transfer)\b", "Government/tax refund impersonation fraud.", "danger", 25),
    ],
    "Credential & Identity Harvesting": [
        (r"\b(verify your (account|identity|password|pin)|update your (billing|information))\b", "Phishing attempt to capture login or personal details.", "danger", 30),
        (r"\b(enter (your|the) (ssn|social security|credit card|cvv|otp|2fa code))\b", "Attempt to harvest highly sensitive credentials / 2FA secrets.", "danger", 35),
        (r"\b(confirm your password|reset password now|re-enter password)\b", "Direct credential phishing language.", "danger", 30),
    ],
    "Brand Impersonation Flags": [
        (r"\b(paypal|apple id|netflix|amazon prime|microsoft support|wells fargo|chase bank|bank of america)\b", "Mentions a frequently impersonated enterprise or financial institution.", "info", 10),
        (r"\b(usps|fedex|dhl|ups package|parcel delivery|delivery failed|customs fee)\b", "Delivery notification smishing pattern.", "warning", 20),
    ],
}

SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
    ".click", ".loan", ".cam", ".surf", ".monster", ".support", ".rest", ".fit"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "bl.ink"
}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
URL_EXTRACTOR = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s/$.?#].[^\s]*", re.IGNORECASE
)

def extract_urls(text):
    urls = []
    for match in URL_EXTRACTOR.finditer(text):
        url = match.group()
        if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("ftp://"):
            url = "http://" + url
        urls.append(url)
    return urls

def analyze_url_pattern(url):
    flags = []
    risk_points = 0

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        netloc = (parsed.netloc or "").lower()

        # Check for plain HTTP
        if parsed.scheme == "http":
            flags.append({
                "category": "Insecure Protocol",
                "indicator": f"http:// scheme used",
                "severity": "warning",
                "reason": "Unencrypted HTTP connection. Legitimate login, banking, and payment sites always require HTTPS.",
            })
            risk_points += 15

        # Check for IP address as hostname
        if IP_REGEX.match(hostname):
            flags.append({
                "category": "Raw IP Hostname",
                "indicator": hostname,
                "severity": "danger",
                "reason": "Uses a bare numerical IP address instead of a recognized domain name, a hallmark of malicious phishing and C2 servers.",
            })
            risk_points += 35

        # Check for @ redirect trick
        if "@" in netloc:
            flags.append({
                "category": "Embedded Redirection (@ Trick)",
                "indicator": netloc,
                "severity": "danger",
                "reason": "Contains '@' in the address. Browsers treat anything before '@' as username and redirect to the host after '@'.",
            })
            risk_points += 40

        # Check for URL Shorteners
        for shortener in URL_SHORTENERS:
            if hostname == shortener or hostname.endswith("." + shortener):
                flags.append({
                    "category": "URL Shortener Masking",
                    "indicator": hostname,
                    "severity": "warning",
                    "reason": f"Uses a URL shortener ({hostname}) to disguise the actual destination link.",
                })
                risk_points += 20
                break

        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                flags.append({
                    "category": "High-Risk Top-Level Domain (TLD)",
                    "indicator": tld,
                    "severity": "warning",
                    "reason": f"Domain ends in '{tld}', an extension disproportionately associated with disposable spam and phishing domains.",
                })
                risk_points += 20
                break

        # Check for excessive hyphens in hostname
        if hostname.count("-") >= 2:
            flags.append({
                "category": "Excessive Hyphenation",
                "indicator": hostname,
                "severity": "warning",
                "reason": "Excessive hyphens in the domain name are frequently used to construct fake typosquatted lookalikes (e.g., 'secure-bank-login-update').",
            })
            risk_points += 15

        # Check for excessive subdomain nesting
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) >= 4:
            flags.append({
                "category": "Deep Subdomain Nesting",
                "indicator": hostname,
                "severity": "warning",
                "reason": "Multiple nested subdomains often attempt to mimic trusted company names within lower subdomains (e.g. paypal.com.attacker.xyz).",
            })
            risk_points += 15

        # Check for non-standard ports
        if parsed.port and parsed.port not in [80, 443]:
            flags.append({
                "category": "Non-Standard Web Port",
                "indicator": f"Port :{parsed.port}",
                "severity": "warning",
                "reason": f"Traffic routed through unusual port {parsed.port} rather than standard HTTP(80)/HTTPS(443).",
            })
            risk_points += 15

        # Hex / percent-encoding obfuscation in path
        if re.search(r"%[0-9a-fA-F]{2}", path):
            flags.append({
                "category": "URL Encoding Obfuscation",
                "indicator": "Hex percent-encoded sequences in path",
                "severity": "info",
                "reason": "Contains hex-encoded characters that may be attempting to bypass automated URL keyword filters.",
            })
            risk_points += 10

    except Exception as e:
        flags.append({
            "category": "Malformed URL",
            "indicator": url,
            "severity": "warning",
            "reason": f"Could not parse URL structure cleanly: {str(e)}",
        })
        risk_points += 15

    return flags, risk_points

def analyze_message_and_link(text, explicit_url=""):
    flags = []
    total_risk = 0

    full_text = text or ""
    clean_url = (explicit_url or "").strip()

    # 1. Analyze text keywords
    text_lower = full_text.lower()
    for cat_name, patterns in SUSPICIOUS_KEYWORDS.items():
        for pattern, explanation, severity, points in patterns:
            match = re.search(pattern, text_lower)
            if match:
                flags.append({
                    "category": cat_name,
                    "indicator": f"Trigger word/phrase: '{match.group()}'",
                    "severity": severity,
                    "reason": explanation,
                })
                total_risk += points

    # 2. Extract and analyze URLs
    urls_to_check = []
    if clean_url:
        if not clean_url.startswith("http://") and not clean_url.startswith("https://") and not clean_url.startswith("ftp://"):
            clean_url = "http://" + clean_url
        urls_to_check.append(clean_url)

    extracted = extract_urls(full_text)
    for u in extracted:
        if u not in urls_to_check:
            urls_to_check.append(u)

    for u in urls_to_check:
        url_flags, url_risk = analyze_url_pattern(u)
        flags.extend(url_flags)
        total_risk += url_risk

    # Normalize risk score 0 - 100
    risk_score = min(100, max(0, total_risk))

    # Determine risk category
    if risk_score >= 70:
        verdict = "DANGEROUS / HIGH RISK"
        verdict_class = "danger"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS / POTENTIAL PHISHING"
        verdict_class = "warning"
    elif risk_score > 10:
        verdict = "LOW RISK / PROCEED WITH CAUTION"
        verdict_class = "info"
    else:
        verdict = "SAFE / NO IMMEDIATE RED FLAGS"
        verdict_class = "success"

    # Generate safety recommendations
    recommendations = []
    if risk_score >= 35 or len(flags) > 0:
        recommendations.append("Do NOT click on any links or download attachments from this message.")
        recommendations.append("Do NOT provide passwords, OTP/2FA codes, credit card details, or personal identification.")
        recommendations.append("Verify through an independent official channel (type the known website URL directly into your browser or call the official phone number).")
        recommendations.append("If this claims to come from your bank or employer, report it immediately to your security department or the organization's fraud desk.")
        if any(f["category"] == "URL Shortener Masking" for f in flags):
            recommendations.append("Use a link expansion service (e.g. checkshorturl.com) to inspect shortened URLs safely before visiting.")
    else:
        recommendations.append("No immediate malicious indicators were detected. However, always verify unknown senders.")
        recommendations.append("Ensure any destination website uses valid HTTPS encryption with a matching certificate.")
        recommendations.append("Never share one-time passcodes (OTP) with anyone, even if they claim to represent technical support.")

    return {
        "text": full_text,
        "checked_urls": urls_to_check,
        "flags": flags,
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "recommendations": recommendations,
        "total_flags": len(flags),
    }
