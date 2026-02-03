import time

import requests
import streamlit as st


st.set_page_config(
    page_title="OSS Dev AssistAgent",
    page_icon="shield",
    layout="wide",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Fraunces:wght@600;700&family=Space+Grotesk:wght@400;500;600&display=swap');

:root {
  --bg: #f8f6f2;
  --panel: #ffffff;
  --ink: #1b1b1f;
  --muted: #6c6c74;
  --accent: #1e6fff;
  --accent-2: #ffb357;
  --border: #e9e5de;
  --shadow: rgba(20, 23, 36, 0.08);
}

html, body, [class*="css"]  {
  font-family: 'Space Grotesk', sans-serif;
}

.stApp {
  background: radial-gradient(1200px 500px at 10% 0%, #fff7eb 0%, rgba(255,247,235,0) 60%),
              radial-gradient(900px 500px at 90% 10%, #eef6ff 0%, rgba(238,246,255,0) 55%),
              var(--bg);
  color: var(--ink);
}

.page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 8px 68px;
}

div[data-testid="stAppViewContainer"] > .main .block-container {
  padding-top: 0.5rem;
}

.hero {
  background: linear-gradient(135deg, #ffffff 0%, #fff8ee 60%, #f1f6ff 100%);
  border: 1px solid var(--border);
  border-radius: 24px;
  padding: 16px;
  box-shadow: 0 24px 50px var(--shadow);
}

.title {
  font-family: 'Fraunces', serif;
  font-size: 44px;
  line-height: 1.05;
  margin-bottom: 8px;
}

.subtitle {
  color: var(--muted);
  font-size: 16px;
  margin-bottom: 20px;
}

.pill {
  display: inline-block;
  padding: 6px 12px;
  border-radius: 999px;
  background: #f3f1ec;
  border: 1px solid var(--border);
  color: #38383f;
  font-size: 12px;
  margin-right: 8px;
}

div[data-testid="stForm"],
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 18px;
  box-shadow: 0 10px 30px var(--shadow);
}

.card + .card {
  margin-top: 16px;
}

.tall-card {
  min-height: 240px;
}

.score-card {
  display: flex;
  flex-direction: column;
}

.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
}

.badge-high {
  background: #ffe6e6;
  color: #b42318;
}

.badge-medium {
  background: #fff3e0;
  color: #b25b00;
}

.badge-low {
  background: #eaf4ff;
  color: #0b4dd8;
}

.summary-card {
  background: linear-gradient(120deg, #fff4e4 0%, #fffaf1 55%, #eef6ff 100%);
  border: 1px solid #ead7bd;
  box-shadow: 0 16px 40px rgba(126, 92, 41, 0.12);
}

.summary-card strong {
  font-size: 22px;
}

.label {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 6px;
}

.muted {
  color: var(--muted);
}

.section-title {
  font-family: 'Fraunces', serif;
  font-size: 28px;
  margin: 32px 0 12px;
}

.section-title.tight {
  margin-top: 16px;
}

.progress-wrap {
  background: #f6efe6;
  border: 1px solid #ead7bd;
  border-radius: 999px;
  padding: 6px 10px;
  min-height: 30px;
  display: flex;
  align-items: center;
  overflow: hidden;
  position: relative;
}

.progress-bar {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  background: #f2a65a;
  transition: width 0.08s ease;
  border-radius: 999px;
}

.progress-label-on {
  position: relative;
  margin-left: auto;
  font-size: 13px;
  font-weight: 600;
  color: #5f3a0a;
}

.progress-block {
  margin: 6px 0 16px;
}

.score-ring {
  width: 140px;
  height: 140px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  margin: 12px auto 0;
}

.score-ring span {
  background: var(--panel);
  width: 110px;
  height: 110px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  font-size: 28px;
  font-weight: 700;
  color: var(--ink);
}

.footer-note {
  margin-top: 22px;
  font-size: 12px;
  color: var(--muted);
}

div[data-testid="stForm"] div[data-testid="stTextInput"] > div > div > input {
  padding: 12px 14px;
  border: 1px solid var(--border);
  background: #ffffff;
  color:black;
}

div[data-testid="stButton"] > button,
div[data-testid="stFormSubmitButton"] > button,
div[data-testid="stFormSubmitButton"] button,
button[kind="primary"],
button[kind="secondary"] {
  color: black !important;
  padding: 10px 18px;
  font-weight: 600;
  transition: transform 0.15s ease;
  background: transparent !important;
  background-color: transparent !important;
  border: 1px solid black !important;
}

div[data-testid="stButton"] > button:hover,
div[data-testid="stFormSubmitButton"] > button:hover,
div[data-testid="stFormSubmitButton"] button:hover,
button[kind="primary"]:hover,
button[kind="secondary"]:hover {
  transform: translateY(-2px);
}

div[data-testid="stButton"] > button:active,
div[data-testid="stFormSubmitButton"] > button:active,
div[data-testid="stFormSubmitButton"] button:active,
button[kind="primary"]:active,
button[kind="secondary"]:active {
  transform: translateY(1px);
}
</style>
<div class="page">
""",
    unsafe_allow_html=True,
)


# API endpoint URL - configured to use port 5003 as per .env
# Since both Flask and Streamlit run on the same server, use localhost
API_ENDPOINT = "http://localhost:5003/upgrade-recommendation"

def fetch_risk_report(github_url: str) -> dict:
    """
    Make a POST API call to analyze the GitHub repository.
    
    Args:
        github_url: The GitHub repository URL to scan
        
    Returns:
        dict: The API response containing risk analysis
    """
    try:
        # Prepare the request body
        payload = {"repo_url": github_url}
        
        # Make the POST API call
        response = requests.post(
            API_ENDPOINT,
            json=payload,
            timeout=30  # 30 second timeout
        )
        
        # Raise an exception for bad status codes
        response.raise_for_status()
        
        # Parse and return the JSON response
        response_data = response.json()
        return response_data
        
    except requests.exceptions.Timeout:
        st.error("Request timed out. Please try again.")
        return None
    except requests.exceptions.ConnectionError:
        st.error(f"Could not connect to API at {API_ENDPOINT}. Please check if the server is running.")
        return None
    except requests.exceptions.HTTPError as e:
        st.error(f"API returned an error: {e}")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        return None

def risk_color_from_score(score: int) -> str:
    if score >= 75:
        return "#e23b2e"
    if score >= 45:
        return "#ffb357"
    return "#2f78ff"


st.markdown(
    """
<div class="hero">
  <div class="title">OSS Dev AssistAgent</div>
  <div class="subtitle">Scan a GitHub repo for risky OSS imports, score the risk, and get safer replacements.</div>
  <span class="pill">Static scan</span>
  <span class="pill">Policy ready</span>
  <span class="pill">Actionable fixes</span>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">How it works</div>', unsafe_allow_html=True)
steps = st.columns(3)
with steps[0]:
    st.markdown(
        '<div class="card"><div class="label">01</div><strong>Collect imports</strong><div class="muted">Parse manifests and source files for OSS usage.</div></div>',
        unsafe_allow_html=True,
    )
with steps[1]:
    st.markdown(
        '<div class="card"><div class="label">02</div><strong>Score risk</strong><div class="muted">Evaluate CVEs, age, and maintenance signals.</div></div>',
        unsafe_allow_html=True,
    )
with steps[2]:
    st.markdown(
        '<div class="card"><div class="label">03</div><strong>Recommend fixes</strong><div class="muted">Suggest upgrades or safer alternatives.</div></div>',
        unsafe_allow_html=True,
    )

st.write("")
top_left, top_right = st.columns([2.2, 1])
report_data = None

with top_left:
    with st.form("repo_form", clear_on_submit=False):
        st.markdown('<div class="label">Repository</div>', unsafe_allow_html=True)
        github_url = st.text_input(
            "GitHub URL",
            placeholder="https://github.com/org/repo",
            label_visibility="collapsed",
            key="github_url",
        )
        st.write("")
        run_scan = st.form_submit_button("Review risk")
        st.markdown(
            '<div class="footer-note">We only read dependency manifests and import statements.</div>',
            unsafe_allow_html=True,
        )
    if run_scan and not github_url:
        st.session_state["github_url_invalid"] = True
    elif github_url:
        st.session_state["github_url_invalid"] = False

    if st.session_state.get("github_url_invalid"):
        st.markdown(
            """
<style>
div[data-testid="stForm"] div[data-testid="stTextInput"] > div > div > input {
  border: 1px solid #e23b2e !important;
}
</style>
""",
            unsafe_allow_html=True,
        )

    if run_scan and github_url:
        with st.spinner("Scanning repository..."):
            report_data = fetch_risk_report(github_url)

with top_right:
    # Calculate risk score from vulnerability data
    if report_data:
        high_count = report_data.get("high_impact_count", 0)
        low_count = report_data.get("low_impact_count", 0)
        total = report_data.get("total_vulnerabilities", 0)
        # Score formula: weighted by severity (high=10, low=3)
        score_value = min(100, (high_count * 10 + low_count * 3) * 5) if total > 0 else 0
    else:
        score_value = None
    ring_color = risk_color_from_score(score_value) if score_value is not None else "#d9dee7"
    ring_fill = score_value if score_value is not None else 0
    score_label = str(score_value) if score_value is not None else "--"
    st.markdown(
        f"""
<div class="card tall-card score-card">
  <div class="label">Risk score</div>
  <div class="score-ring" style="background: conic-gradient({ring_color} 0 {ring_fill}%, #e9edf4 {ring_fill}% 100%);">
    <span>{score_label}</span>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

st.markdown('<div class="section-title tight">Risk suggestions</div>', unsafe_allow_html=True)

if run_scan and github_url:
    progress_slot = st.empty()
    for step in range(0, 101, 4):
        percent = min(step, 100)
        progress_slot.markdown(
            f"""
<div class="progress-block">
<div class="progress-wrap">
    <div class="progress-bar" style="width: {percent}%;"></div>
    <div class="progress-label-on">{percent}%</div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
        time.sleep(0.12)
    report = report_data or fetch_risk_report(github_url)
    if report:
        high_count = report.get("high_impact_count", 0)
        low_count = report.get("low_impact_count", 0)
        total = report.get("total_vulnerabilities", 0)
        
        # Calculate risk score
        calc_score = min(100, (high_count * 10 + low_count * 3) * 5) if total > 0 else 0
        
        # Build summary text
        summary_parts = []
        if high_count > 0:
            summary_parts.append(f"{high_count} high-impact")
        if low_count > 0:
            summary_parts.append(f"{low_count} low-impact")
        summary_text = ", ".join(summary_parts) + " vulnerabilities" if summary_parts else "No vulnerabilities found"
        
        st.markdown(
            f"""
<div class="card summary-card">
  <div class="label">Summary</div>
  <strong>Risk score {calc_score}</strong>
  <div class="muted">{summary_text} • Total: {total}</div>
</div>
""",
            unsafe_allow_html=True,
        )
        
        # Combine high and low impact items with their severity
        all_items = []
        for item_data in report.get("high_impact", []):
            for package_name, details in item_data.items():
                all_items.append(("High", package_name, details))
        for item_data in report.get("low_impact", []):
            for package_name, details in item_data.items():
                all_items.append(("Low", package_name, details))
        
        # Render each vulnerability
        for impact_level, package_name, details in all_items:
            badge_class = "badge-high" if impact_level == "High" else "badge-low"
            severity = details.get("severity", "UNKNOWN")
            version = details.get("version", "N/A")
            fixed_in = details.get("fixed_in", "N/A")
            vuln_id = details.get("vulnerability_id", "N/A")
            vuln_summary = details.get("vulnerability_summary", "No summary available")
            risk_summary = details.get("risk_summary", "")
            
            # Get AI recommendation if available
            ai_rec = details.get("ai_recommendation", {})
            decision = ai_rec.get("decision", "")
            reasoning = ai_rec.get("reasoning", "")
            
            suggestion = f"Upgrade to version {fixed_in}" if fixed_in != "N/A" else "Check for updates"
            if decision:
                suggestion += f" ({decision})"
            
            st.markdown(
                f"""
<div class="card">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <strong>{package_name} {version}</strong>
    <span class="badge {badge_class}">{impact_level} impact • {severity}</span>
  </div>
  <div class="muted" style="margin-top:6px;">Vulnerability ID: {vuln_id}</div>
  <div class="muted">Issue: {vuln_summary}</div>
  <div style="margin-top:10px;"><strong>Suggestion:</strong> {suggestion}</div>
  <div class="muted" style="margin-top:6px;">{risk_summary}</div>
  {f'<div class="muted" style="margin-top:6px;"><strong>AI Analysis:</strong> {reasoning}</div>' if reasoning else ''}
</div>
""",
                unsafe_allow_html=True,
            )
    else:
        st.error("Failed to retrieve vulnerability report. Please try again.")
else:
    st.markdown(
        '<div class="card"><strong>No scan yet</strong><div class="muted">Enter a GitHub URL and press "Review risk" to see suggestions.</div></div>',
        unsafe_allow_html=True,
    )

st.markdown(
    """
<style>
div[data-testid="stForm"] {
  border: 1px solid var(--border);
  padding: 18px;
  box-shadow: 0 10px 30px var(--shadow);
  min-height: 240px;
  display: flex;
  flex-direction: column;
}
</style>
""",
    unsafe_allow_html=True,
)


st.markdown("</div>", unsafe_allow_html=True)
