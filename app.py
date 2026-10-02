
import math
import re
import ipaddress
from collections import Counter
from urllib.parse import urlparse

import joblib
import streamlit as st

st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="wide",
)

MODEL_FILE = "phishing_random_forest.joblib"

RISK_LEVELS = {
    "Safe": {
        "color": "#20c997",
        "background": "#e9fbf4",
        "description": "The ML model considers this URL more likely to be legitimate.",
    },
    "Suspicious": {
        "color": "#f5a524",
        "background": "#fff7e6",
        "description": "The ML model sees mixed signals, so the URL should be treated carefully.",
    },
    "High Risk": {
        "color": "#f15b5d",
        "background": "#fff0f0",
        "description": "The ML model considers this URL more likely to be phishing.",
    },
}

@st.cache_resource
def load_model():
    return joblib.load(MODEL_FILE)

def normalize_url(raw_url):
    value = raw_url.strip()
    if value and not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        value = "https://" + value
    return value

def is_ip_address(hostname):
    try:
        ipaddress.ip_address((hostname or "").strip("[]"))
        return 1
    except ValueError:
        return 0

def shannon_entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())

def extract_features(raw_url):
    """
    Extract the same 13 URL features used by the trained Random Forest.
    The training dataset already contained these numerical URL features.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    labels = [label for label in hostname.split(".") if label]

    if len(labels) >= 2:
        subdomain_count = max(len(labels) - 2, 0)
        domain_name_length = len(labels[-2])
    else:
        subdomain_count = 0
        domain_name_length = len(hostname)

    # The supplied dataset records at least one query-parameter count
    # for URLs without a query, so we preserve that convention.
    query_param_count = len(parsed.query.split("&")) if parsed.query else 1

    digits = sum(ch.isdigit() for ch in url)
    path = parsed.path or "/"

    suspicious_extensions = (
        ".exe", ".zip", ".scr", ".bat", ".cmd",
        ".msi", ".jar", ".apk", ".dmg", ".iso"
    )

    features = {
        "url_length": len(url),
        "has_ip_address": is_ip_address(hostname),
        "dot_count": url.count("."),
        "https_flag": 1 if parsed.scheme.lower() == "https" else 0,
        "url_entropy": shannon_entropy(url),
        "subdomain_count": subdomain_count,
        "query_param_count": query_param_count,
        "path_length": len(path),
        "has_hyphen_in_domain": 1 if "-" in hostname else 0,
        "number_of_digits": digits,
        "suspicious_file_extension": 1 if any(
            path.lower().endswith(ext) for ext in suspicious_extensions
        ) else 0,
        "domain_name_length": domain_name_length,
        "percentage_numeric_chars": (digits / len(url) * 100) if url else 0.0,
    }
    return features

def predict_url(raw_url):
    artifact = load_model()
    features = artifact["features"]
    medians = artifact["medians"]
    model = artifact["model"]

    extracted = extract_features(raw_url)
    row = [extracted.get(name, medians.get(name, 0)) for name in features]

    probabilities = model.predict_proba([row])[0]
    class_index = {int(cls): i for i, cls in enumerate(model.classes_)}

    phishing_probability = float(probabilities[class_index[0]])
    legitimate_probability = float(probabilities[class_index[1]])

    predicted_class = 0 if phishing_probability >= 0.5 else 1

    # Three-level display is only a presentation layer.
    # The underlying Random Forest is binary: phishing vs legitimate.
    if phishing_probability >= 0.75:
        risk = "High Risk"
    elif phishing_probability >= 0.35:
        risk = "Suspicious"
    else:
        risk = "Safe"

    return {
        "normalized": normalize_url(raw_url),
        "risk": risk,
        "predicted_class": predicted_class,
        "prediction": "Phishing" if predicted_class == 0 else "Legitimate",
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "features": extracted,
    }

def inject_styles():
    st.markdown(
        """
        <style>
        :root {
            --ink: #14213d;
            --muted: #667085;
            --line: #e8eaf0;
            --blue: #315efb;
        }
        .stApp {
            background: #f8f9fc;
            color: var(--ink);
        }
        [data-testid="stSidebar"] {
            background: #111b36;
        }
        [data-testid="stSidebar"] * {
            color: #e8edff;
        }
        .brand-mark {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 42px;
            font-size: 18px;
            font-weight: 700;
        }
        .shield {
            display: grid;
            place-items: center;
            width: 34px;
            height: 38px;
            background: #315efb;
            color: white;
            clip-path: polygon(50% 0, 90% 15%, 87% 65%, 50% 100%, 13% 65%, 10% 15%);
        }
        .side-label {
            color: #7e8bb0 !important;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.4px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .result-card {
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 27px;
            background: white;
            margin-top: 28px;
            box-shadow: 0 8px 30px rgba(20, 33, 61, .04);
        }
        .result-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 16px;
        }
        .result-kicker {
            color: #8a93a7;
            text-transform: uppercase;
            letter-spacing: 1.4px;
            font-size: 11px;
            font-weight: 700;
        }
        .result-name {
            font-size: 30px;
            font-weight: 700;
            margin-top: 6px;
        }
        .url-preview {
            margin-top: 22px;
            padding: 13px 15px;
            border-radius: 9px;
            background: #f5f6fa;
            color: #556078;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def render_result(result):
    level = RISK_LEVELS[result["risk"]]
    phishing_pct = result["phishing_probability"] * 100
    legitimate_pct = result["legitimate_probability"] * 100

    st.markdown(
        f"""
        <div class="result-card">
            <div class="result-top">
                <div>
                    <div class="result-kicker">ML Assessment</div>
                    <div class="result-name" style="color:{level['color']};">
                        {result['risk']}
                    </div>
                </div>
                <div style="color:{level['color']};background:{level['background']};
                            border-radius:99px;padding:8px 13px;font-size:12px;font-weight:700;">
                    {result['prediction']}
                </div>
            </div>
            <div style="color:#667085;font-size:14px;margin-top:8px;">
                {level['description']}
            </div>
            <div class="url-preview">{result['normalized']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Phishing probability", f"{phishing_pct:.2f}%")
    with col2:
        st.metric("Legitimate probability", f"{legitimate_pct:.2f}%")

    st.markdown("### Features used by the Random Forest")
    st.caption("The model uses URL characteristics from the trained dataset, not the old manual risk-point rules.")

    display_names = {
        "url_length": "URL length",
        "has_ip_address": "IP address in host",
        "dot_count": "Dot count",
        "https_flag": "HTTPS flag",
        "url_entropy": "URL entropy",
        "subdomain_count": "Subdomain count",
        "query_param_count": "Query parameter count",
        "path_length": "Path length",
        "has_hyphen_in_domain": "Hyphen in domain",
        "number_of_digits": "Number of digits",
        "suspicious_file_extension": "Suspicious file extension",
        "domain_name_length": "Domain name length",
        "percentage_numeric_chars": "Numeric character percentage",
    }

    for name, value in result["features"].items():
        st.write(f"**{display_names.get(name, name)}:** {value:.4f}" if isinstance(value, float) else f"**{display_names.get(name, name)}:** {value}")

def main():
    inject_styles()

    with st.sidebar:
        st.markdown('<div class="brand-mark"><span class="shield">✓</span> URL Guard ML</div>', unsafe_allow_html=True)
        st.markdown('<div class="side-label">How it works</div>', unsafe_allow_html=True)
        st.write(
            "The URL is converted into numerical features and passed to a trained "
            "Random Forest classifier. The model predicts phishing or legitimate."
        )
        st.markdown('<div class="side-label" style="margin-top:28px;">Model</div>', unsafe_allow_html=True)
        st.write("Random Forest")
        st.write("Dataset: LegitPhish")
        st.write("Binary classification: Phishing / Legitimate")

    st.markdown('<div style="color:#315efb;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1.7px;">Machine Learning URL analysis</div>', unsafe_allow_html=True)
    st.title("Phishing Website Detection")
    st.markdown(
        '<div style="max-width:660px;color:#667085;font-size:16px;line-height:1.65;">'
        'Enter a URL and let the trained Random Forest model analyze its URL characteristics.'
        '</div>',
        unsafe_allow_html=True,
    )

    with st.form("url_form"):
        col_input, col_button = st.columns([5, 1])
        with col_input:
            raw_url = st.text_input(
                "URL",
                placeholder="example.com/login",
                label_visibility="collapsed",
            )
        with col_button:
            submitted = st.form_submit_button("Analyze", use_container_width=True)

    st.caption("The model analyzes the URL features only. It does not open the website.")

    if submitted:
        if not raw_url.strip():
            st.warning("Enter a URL first.")
            return

        parsed = urlparse(normalize_url(raw_url))
        if not parsed.hostname:
            st.error("That does not look like a valid URL.")
            return

        try:
            render_result(predict_url(raw_url))
        except Exception as exc:
            st.error("The ML model could not analyze this URL.")
            st.exception(exc)
    else:
        st.markdown(
            """
            <div class="result-card" style="background:#fbfcfe;">
                <div class="result-kicker">Ready</div>
                <div style="font-size:22px;font-weight:700;margin-top:7px;">
                    Paste a link to see the ML prediction.
                </div>
                <div style="color:#667085;font-size:14px;margin-top:8px;line-height:1.6;">
                    This prototype is for educational use. ML predictions are not a guarantee that a website is safe.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

if __name__ == "__main__":
    main()
