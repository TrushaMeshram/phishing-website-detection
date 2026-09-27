import ipaddress
import re
from urllib.parse import parse_qsl, urlparse

import streamlit as st


st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


RISK_LEVELS = {
    "Safe": {
        "color": "#20c997",
        "background": "#e9fbf4",
        "description": "No major warning signs were found in this URL.",
    },
    "Suspicious": {
        "color": "#f5a524",
        "background": "#fff7e6",
        "description": "Some characteristics deserve a closer look before you continue.",
    },
    "High Risk": {
        "color": "#f15b5d",
        "background": "#fff0f0",
        "description": "Several strong phishing indicators were detected. Avoid opening it.",
    },
}


def normalize_url(raw_url: str) -> str:
    """Add a scheme when a user enters only a domain."""
    value = raw_url.strip()
    if value and not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        value = f"https://{value}"
    return value


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(raw_url: str) -> dict:
    """Return transparent URL-only signals and a simple weighted risk score."""
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    labels = [label for label in hostname.split(".") if label]
    subdomains = max(len(labels) - 2, 0)
    query_params = parse_qsl(parsed.query, keep_blank_values=True)

    checks = []

    def add_check(name: str, detail: str, points: int, positive: bool = False):
        checks.append(
            {
                "name": name,
                "detail": detail,
                "points": points,
                "positive": positive,
            }
        )

    if parsed.scheme == "https":
        add_check("HTTPS enabled", "The connection uses HTTPS.", 0, True)
    else:
        add_check("No HTTPS", "The URL uses plain HTTP, so traffic is not encrypted.", 2)

    if hostname and is_ip_address(hostname):
        add_check("IP address host", "The host is an IP address instead of a named domain.", 3)
    else:
        add_check("Named domain", "The host uses a readable domain name.", 0, True)

    if "@" in parsed.netloc:
        add_check(
            "At-sign in address",
            "Text before @ can disguise the real destination host.",
            3,
        )
    else:
        add_check("No @ symbol", "The address does not hide a host behind an @ symbol.", 0, True)

    if len(normalized) > 100:
        add_check("Very long URL", f"The URL is {len(normalized)} characters long.", 2)
    elif len(normalized) > 75:
        add_check("Long URL", f"The URL is {len(normalized)} characters long.", 1)
    else:
        add_check("Moderate URL length", f"The URL is {len(normalized)} characters long.", 0, True)

    if subdomains >= 4:
        add_check("Many subdomains", f"The domain has {subdomains} subdomains.", 2)
    elif subdomains == 3:
        add_check("Several subdomains", f"The domain has {subdomains} subdomains.", 1)
    else:
        add_check("Simple domain structure", "The domain has a typical number of subdomains.", 0, True)

    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        add_check("Many hyphens", f"The host contains {hyphen_count} hyphens.", 2)
    elif hyphen_count:
        add_check("Hyphenated host", f"The host contains {hyphen_count} hyphen.", 1)
    else:
        add_check("No unusual hyphens", "The host does not use repeated hyphens.", 0, True)

    if re.search(r"(login|signin|verify|update|secure|account|payment|wallet|password)", path_and_query, re.I):
        add_check(
            "Sensitive wording",
            "The path or query asks about an account, payment, login, or verification.",
            2,
        )
    else:
        add_check("No sensitive wording", "No common credential-baiting words were found.", 0, True)

    if len(query_params) >= 5:
        add_check("Many query parameters", f"The URL contains {len(query_params)} query parameters.", 1)
    else:
        add_check("Limited query parameters", f"The URL contains {len(query_params)} query parameters.", 0, True)

    if any(token in hostname for token in ("xn--", "bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd")):
        add_check(
            "Obfuscated or shortened host",
            "The host uses an IDN marker or a commonly shortened-domain pattern.",
            2,
        )
    else:
        add_check("No shortening pattern", "No common URL-shortener pattern was found.", 0, True)

    score = sum(check["points"] for check in checks)
    if score >= 7:
        classification = "High Risk"
    elif score >= 3:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return {
        "normalized": normalized,
        "scheme": parsed.scheme,
        "hostname": hostname or "Not detected",
        "path": parsed.path or "/",
        "score": score,
        "classification": classification,
        "checks": checks,
    }


def inject_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');

        :root {
            --ink: #14213d;
            --muted: #667085;
            --line: #e8eaf0;
            --blue: #315efb;
        }
        .stApp {
            background: #f8f9fc;
            color: var(--ink);
            font-family: 'Space Grotesk', sans-serif;
        }
        [data-testid="stHeader"] { background: transparent; }
        [data-testid="stSidebar"] {
            background: #111b36;
            border-right: 0;
        }
        [data-testid="stSidebar"] * { color: #e8edff; }
        [data-testid="stSidebar"] .stMarkdown p { color: #aeb9db; }
        .brand-mark {
            display: flex; align-items: center; gap: 12px; margin-bottom: 42px;
            font-size: 18px; font-weight: 700; letter-spacing: -0.4px;
        }
        .shield {
            display: grid; place-items: center; width: 34px; height: 38px;
            background: #315efb; color: white; clip-path: polygon(50% 0, 90% 15%, 87% 65%, 50% 100%, 13% 65%, 10% 15%);
            font-size: 18px;
        }
        .side-label {
            color: #7e8bb0 !important; font-size: 11px; text-transform: uppercase;
            letter-spacing: 1.4px; font-weight: 700; margin-bottom: 8px;
        }
        .side-note {
            margin-top: 40px; padding-top: 18px; border-top: 1px solid #2d3858;
            color: #aeb9db; font-size: 12px; line-height: 1.6;
        }
        .eyebrow {
            color: var(--blue); font-size: 12px; font-weight: 700;
            text-transform: uppercase; letter-spacing: 1.7px; margin-top: 10px;
        }
        h1 {
            color: var(--ink); font-size: clamp(34px, 5vw, 58px) !important;
            letter-spacing: -2.6px; line-height: 1.02 !important; margin: 9px 0 16px !important;
        }
        .subtitle { max-width: 660px; color: var(--muted); font-size: 16px; line-height: 1.65; }
        .url-label { color: var(--ink); font-size: 13px; font-weight: 700; margin: 30px 0 9px; }
        div[data-testid="stTextInput"] input {
            border: 1px solid #d9dfea; border-radius: 10px; min-height: 48px;
            font-family: 'DM Mono', monospace; font-size: 13px; background: white;
        }
        div[data-testid="stTextInput"] input:focus { border-color: var(--blue); box-shadow: 0 0 0 1px var(--blue); }
        .stButton > button {
            min-height: 48px; border: 0; border-radius: 10px; background: var(--blue);
            color: white; font-family: 'Space Grotesk', sans-serif; font-weight: 700;
        }
        .stButton > button:hover { background: #244bdd; color: white; }
        .example-caption { color: #7c8498; font-size: 12px; margin-top: 10px; }
        .result-card {
            border: 1px solid var(--line); border-radius: 18px; padding: 27px;
            background: white; margin-top: 28px; box-shadow: 0 8px 30px rgba(20, 33, 61, .04);
        }
        .result-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
        .result-kicker { color: #8a93a7; text-transform: uppercase; letter-spacing: 1.4px; font-size: 11px; font-weight: 700; }
        .result-name { font-size: 30px; font-weight: 700; letter-spacing: -1.1px; margin-top: 6px; }
        .risk-badge {
            border-radius: 99px; padding: 8px 13px; font-size: 12px; font-weight: 700; white-space: nowrap;
        }
        .score-row { display: flex; align-items: center; gap: 13px; margin-top: 24px; }
        .score-track { height: 9px; background: #eef0f5; border-radius: 10px; flex: 1; overflow: hidden; }
        .score-fill { height: 100%; border-radius: 10px; }
        .score-number { font-family: 'DM Mono', monospace; font-size: 13px; color: #566078; }
        .url-preview {
            margin-top: 22px; padding: 13px 15px; border-radius: 9px; background: #f5f6fa;
            color: #556078; font-family: 'DM Mono', monospace; font-size: 12px; word-break: break-all;
        }
        .section-heading { font-size: 18px; font-weight: 700; margin: 32px 0 5px; }
        .section-sub { color: var(--muted); font-size: 13px; margin-bottom: 15px; }
        .signal {
            display: flex; justify-content: space-between; gap: 12px; align-items: center;
            border-bottom: 1px solid #eef0f4; padding: 13px 0;
        }
        .signal:last-child { border-bottom: 0; }
        .signal-name { font-size: 13px; font-weight: 600; }
        .signal-detail { color: #7b8498; font-size: 12px; margin-top: 3px; line-height: 1.4; }
        .signal-points { font-family: 'DM Mono', monospace; font-size: 12px; white-space: nowrap; }
        .footer-note { color: #8a93a7; font-size: 11px; line-height: 1.5; margin-top: 32px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar():
    with st.sidebar:
        st.markdown('<div class="brand-mark"><span class="shield">✓</span> URL Guard</div>', unsafe_allow_html=True)
        st.markdown('<div class="side-label">How it works</div>', unsafe_allow_html=True)
        st.markdown(
            "We inspect visible URL characteristics and add points for common phishing signals. No page is opened and no data is sent anywhere.",
            unsafe_allow_html=True,
        )
        st.markdown('<div class="side-label" style="margin-top:28px;">Risk scale</div>', unsafe_allow_html=True)
        st.markdown("**Safe** · 0–2 points", unsafe_allow_html=True)
        st.markdown("**Suspicious** · 3–6 points", unsafe_allow_html=True)
        st.markdown("**High Risk** · 7+ points", unsafe_allow_html=True)
        st.markdown(
            '<div class="side-note">A URL check is a quick signal, not a guarantee. Treat unexpected links carefully even when they score Safe.</div>',
            unsafe_allow_html=True,
        )


def render_result(result: dict):
    level = RISK_LEVELS[result["classification"]]
    score_percent = min(result["score"] / 12 * 100, 100)
    st.markdown(
        f"""
        <div class="result-card">
            <div class="result-top">
                <div>
                    <div class="result-kicker">Assessment</div>
                    <div class="result-name" style="color:{level['color']};">{result['classification']}</div>
                </div>
                <div class="risk-badge" style="color:{level['color']}; background:{level['background']};">
                    {result['score']} risk points
                </div>
            </div>
            <div style="color:#667085; font-size:14px; margin-top:8px;">{level['description']}</div>
            <div class="score-row">
                <div class="score-track"><div class="score-fill" style="width:{score_percent}%; background:{level['color']};"></div></div>
                <div class="score-number">{result['score']} / 12+</div>
            </div>
            <div class="url-preview">{result['normalized']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-heading">What we found</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">Each signal is shown so you can understand the decision.</div>',
        unsafe_allow_html=True,
    )
    for check in result["checks"]:
        if check["positive"]:
            icon = "✓"
            icon_color = "#20a779"
            points = "No points"
        else:
            icon = "!"
            icon_color = "#e39518" if check["points"] < 3 else "#e05255"
            points = f"+{check['points']} points"
        st.markdown(
            f"""
            <div class="signal">
                <div style="display:flex; gap:10px;">
                    <div style="width:20px; height:20px; border-radius:50%; background:{icon_color}18; color:{icon_color}; text-align:center; line-height:20px; font-weight:700; font-size:12px;">{icon}</div>
                    <div><div class="signal-name">{check['name']}</div><div class="signal-detail">{check['detail']}</div></div>
                </div>
                <div class="signal-points" style="color:{icon_color};">{points}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def main():
    inject_styles()
    render_sidebar()

    st.markdown('<div class="eyebrow">Simple URL analysis</div>', unsafe_allow_html=True)
    st.title("Phishing Website Detection")
    st.markdown(
        '<div class="subtitle">Check a link before you click. We look at basic URL characteristics and explain the signals behind every result.</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="url-label">URL to analyze</div>', unsafe_allow_html=True)
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

    st.markdown(
        '<div class="example-caption">Try an example: <code>https://accounts.example.com/verify</code> or <code>https://www.python.org</code></div>',
        unsafe_allow_html=True,
    )

    if submitted:
        if not raw_url.strip():
            st.warning("Enter a URL first so there is something to analyze.")
        else:
            parsed = urlparse(normalize_url(raw_url))
            if not parsed.hostname:
                st.error("That does not look like a valid URL. Try entering a domain such as example.com.")
            else:
                render_result(analyze_url(raw_url))
    else:
        st.markdown(
            """
            <div class="result-card" style="background:#fbfcfe;">
                <div class="result-kicker">Ready when you are</div>
                <div style="font-size:22px; font-weight:700; margin-top:7px;">Paste a link to see its risk signals.</div>
                <div style="color:#667085; font-size:14px; margin-top:8px; line-height:1.6;">This tool only examines the text of the URL. It does not visit the site, download content, or guarantee that a link is safe.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="footer-note">For educational use. This lightweight heuristic is not a replacement for browser security warnings or professional threat intelligence.</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()