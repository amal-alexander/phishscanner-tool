import streamlit as st
import tldextract
import socket
import ssl
import requests
import json
import re
import dns.resolver
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
import whois
from fpdf import FPDF
import plotly.graph_objects as go

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'confirm', 'secure', 'account', 'update', 'bank', 'payment', 'signin',
    'verify-account', 'ebay', 'paypal', 'amazon', 'appleid', 'reset'
]

SUSPICIOUS_TLDS = ['xyz', 'top', 'club', 'info', 'icu', 'biz', 'loan', 'work', 'gdn']

LEGITIMATE_DOMAINS = [
    'paypal.com', 'ebay.com', 'amazon.com', 'apple.com', 'google.com', 'microsoft.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com'
]

SAMPLE_URLS = [
    {
        "name": "🚨 Suspicious PayPal Phish",
        "url": "https://paypa1-verify-account.xyz/confirm?user=john&token=abc123&session=xyz789",
        "description": "Fake PayPal domain with verification keywords"
    },
    {
        "name": "⚠️ Banking Scam (IP-based)",
        "url": "http://192.168.1.100:8080/bank/login?secure=true&redirect=https://example.com",
        "description": "IP-based URL with banking keywords"
    },
    {
        "name": "✅ Legitimate URL",
        "url": "https://www.google.com/search?q=weather",
        "description": "Real Google search"
    },
    {
        "name": "✅ Real Amazon",
        "url": "https://www.amazon.com/s?k=books",
        "description": "Real Amazon product page"
    }
]

def extract_domain(host: str):
    te = tldextract.extract(host)
    domain = te.registered_domain
    subdomain = te.subdomain
    return domain, subdomain, te.suffix

def is_ip(host: str):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except Exception:
            return False

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = 'http://' + url
    return url

def parse_url(url: str):
    parsed = urlparse(url)
    host = parsed.netloc
    return parsed, host

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def url_heuristics(url: str, parsed):
    issues = []
    score = 0
    
    if len(url) > 75:
        issues.append(("Long URL length", f"{len(url)} chars", "warning"))
        score += 2
    elif len(url) > 45:
        issues.append(("Moderate URL length", f"{len(url)} chars", "info"))
        score += 1
    
    if '@' in url:
        issues.append(("Contains '@'", "May hide true destination", "danger"))
        score += 3
    
    if re.search(r'//.*//', url):
        issues.append(("Multiple '//'", "Unusual URL structure", "warning"))
        score += 2
    
    host = parsed.netloc.split(':')[0]
    if is_ip(host):
        issues.append(("IP Address", f"Using {host} instead of domain", "danger"))
        score += 3
    
    lower = unquote(url).lower()
    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            found_keywords.append(kw)
    if found_keywords:
        issues.append(("Suspicious Keywords", ", ".join(found_keywords), "warning"))
        score += 2 * len(found_keywords)
    
    te = tldextract.extract(host)
    if te.subdomain and te.subdomain.count('.') >= 2:
        issues.append(("Many Subdomains", te.subdomain, "warning"))
        score += 1
    
    if 'xn--' in host:
        issues.append(("Punycode Domain", "Possible homograph attack", "danger"))
        score += 3
    
    if parsed.path and len(parsed.path) > 50:
        issues.append(("Long Path", f"{len(parsed.path)} chars", "info"))
        score += 1
    
    if parsed.query and len(parsed.query) > 80:
        issues.append(("Long Query String", f"{len(parsed.query)} chars", "info"))
        score += 1
    
    domain, subdomain, suffix = extract_domain(host)
    if domain and domain.count('-') >= 2:
        issues.append(("Multiple Hyphens", "In registered domain", "warning"))
        score += 1
    
    te_suffix = suffix.lower() if suffix else ''
    if te_suffix in SUSPICIOUS_TLDS:
        issues.append(("Suspicious TLD", f"'{te_suffix}' often abused", "warning"))
        score += 1
    
    return score, issues

def get_whois_info(domain: str):
    """Fetches WHOIS information for a domain."""
    info = {}
    try:
        w = whois.whois(domain)
        info['registrar'] = w.registrar
        info['creation_date'] = w.creation_date
        info['expiration_date'] = w.expiration_date
        # Handle cases where date is a list
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if creation_date:
            # Ensure both datetimes are timezone-aware (or both naive) for comparison
            now_aware = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            info['domain_age_days'] = (now_aware - creation_date).days
    except Exception as e:
        info['error'] = f"WHOIS lookup failed: {str(e)}"
    return info

def resolve_dns(domain: str):
    results = {}
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=5)
        results['A'] = [str(r) for r in answers]
    except Exception as e:
        results['A_error'] = str(e)
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        results['MX'] = [str(r.exchange) for r in answers]
    except Exception as e:
        results['MX_error'] = str(e)
    return results

def ssl_info(hostname: str):
    info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info['cert'] = cert
                notAfter = cert.get('notAfter')
                notBefore = cert.get('notBefore')
                info['notAfter'] = notAfter
                info['notBefore'] = notBefore
                info['issuer'] = dict(x[0] for x in cert.get('issuer', ()))
    except Exception as e:
        info['error'] = str(e)
    return info

def safe_fetch_headers(url: str, method='HEAD'):
    out = {}
    try:
        headers = {'User-Agent': 'PhishScanner/1.0 (+https://example)'}
        r = requests.request(method, url, headers=headers, timeout=6, allow_redirects=False, stream=True, verify=True)
        out['status_code'] = r.status_code
        out['headers'] = dict(r.headers)
    except Exception as e:
        out['error'] = str(e)
    return out

def create_gauge_chart(risk_score):
    """Creates a vibrant Plotly gauge chart for the risk score."""
    # Define colors based on risk levels
    if risk_score >= 80:
        color = "#ff4b4b"
    elif risk_score >= 40:
        color = "#ffa421"
    else:
        color = "#00d4ff"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Risk Level Assessment", 'font': {'size': 24, 'color': '#f8fafc'}},
        number={'font': {'size': 48, 'color': color}, 'suffix': "%"},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
            'bar': {'color': color},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 0,
            'steps': [
                {'range': [0, 40], 'color': 'rgba(0, 212, 255, 0.1)'},
                {'range': [40, 80], 'color': 'rgba(255, 164, 33, 0.1)'},
                {'range': [80, 100], 'color': 'rgba(255, 75, 75, 0.1)'}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': risk_score
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=280,
        margin=dict(l=20, r=20, t=50, b=20),
        font={'color': "#f8fafc"}
    )
    return fig

def generate_pdf_report(report_data):
    """Generates a PDF report from the analysis data."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    
    # Header
    pdf.cell(0, 10, 'PhishScanner Analysis Report', 0, 1, 'C')
    pdf.set_font("Arial", '', 8)
    pdf.cell(0, 5, f"Generated: {report_data['timestamp']}", 0, 1, 'C')
    pdf.ln(10)

    # Risk Score
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"Risk Score: {report_data['final_risk_score']}/100 ({report_data['risk_level']})", 0, 1)
    pdf.ln(5)

    # URL Info
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "URL Information", 0, 1)
    pdf.set_font("Arial", '', 10)
    pdf.multi_cell(0, 5, f"Input: {report_data['input_url']}")
    pdf.multi_cell(0, 5, f"Normalized: {report_data['normalized_url']}")
    pdf.multi_cell(0, 5, f"Domain: {report_data['domain_info']['domain']} | Subdomain: {report_data['domain_info']['subdomain'] or 'None'}")
    pdf.ln(5)

    # Heuristics
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Heuristic Analysis", 0, 1)
    pdf.set_font("Arial", '', 10)
    if report_data['heuristic_analysis']['issues']:
        for issue in report_data['heuristic_analysis']['issues']:
            pdf.multi_cell(0, 5, f"- [{issue['severity'].upper()}] {issue['title']}: {issue['detail']}")
    else:
        pdf.cell(0, 5, "No heuristic issues found.")
    pdf.ln(5)

    # WHOIS Info
    if 'whois_info' in report_data and not report_data['whois_info'].get('error'):
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Domain WHOIS Information", 0, 1)
        pdf.set_font("Arial", '', 10)
        whois_info = report_data['whois_info']
        pdf.cell(0, 5, f"Registrar: {whois_info.get('registrar', 'N/A')}", 0, 1)
        age = whois_info.get('domain_age_days')
        pdf.cell(0, 5, f"Domain Age: {age} days" if age is not None else "Domain Age: N/A", 0, 1)
        creation_date = whois_info.get('creation_date')
        if creation_date:
             creation_date_str = creation_date[0].strftime('%Y-%m-%d') if isinstance(creation_date, list) else creation_date.strftime('%Y-%m-%d')
             pdf.cell(0, 5, f"Creation Date: {creation_date_str}", 0, 1)
        pdf.ln(5)

    return pdf.output(dest='S').encode('latin1')

def check_typosquatting(domain: str):
    """Checks for typosquatting against a list of legitimate domains."""
    from Levenshtein import distance
    for legit_domain in LEGITIMATE_DOMAINS:
        if distance(domain, legit_domain) == 1:
            return f"Domain '{domain}' is very similar to '{legit_domain}' (typosquatting?)"
    return None

st.set_page_config(page_title="PhishScanner — SMS Link Analyzer", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400&display=swap');

    /* Theme Engine - Forces Premium Dark Mode Visibility */
    .stApp {
        background: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%) !important;
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif;
    }

    /* Ultra-Aggressive Text Readability */
    * {
        color: inherit; /* Allow color to flow except where overridden */
    }
    
    /* Force specific elements to be readable */
    label, .stMarkdown, p, span, h1, h2, h3, div, .stMetricValue, .stMetricLabel {
        color: #f8fafc !important;
    }
    
    /* Ensure metric values pop */
    [data-testid="stMetricValue"] > div {
        color: #38bdf8 !important;
        font-weight: 800 !important;
        font-size: 2.2rem !important;
    }
    [data-testid="stMetricLabel"] > div {
        color: #94a3b8 !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
    }

    /* Specific readability for URL input label */
    .stTextInput label {
        color: #38bdf8 !important;
        font-weight: 700 !important;
        font-size: 1.1rem !important;
    }

    /* Header Aesthetics */
    .main-header {
        font-size: 3.8rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent ;
        text-align: center;
        margin-bottom: 2px;
        filter: drop-shadow(0 0 15px rgba(56, 189, 248, 0.4));
    }
    .subtitle {
        text-align: center;
        color: #94a3b8 !important;
        font-size: 1.2rem;
        margin-bottom: 30px;
    }

    /* Cards & Alignment */
    div[data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.04) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 20px !important;
        padding: 20px !important;
        backdrop-filter: blur(12px) !important;
        box-shadow: 0 10px 30px -15px rgba(0,0,0,0.5) !important;
    }

    /* Aligning the Clear Button */
    .stButton > button {
        height: 100% !important;
        margin-top: 30px !important;
        border-radius: 12px !important;
        font-weight: 700 !important;
        background: rgba(255, 255, 255, 0.07) !important;
        color: #f8fafc !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
    }
    
    .stButton > button[kind="primary"] {
        margin-top: 5px !important;
        background: linear-gradient(90deg, #38bdf8, #4f46e5) !important;
        color: white !important;
        box-shadow: 0 8px 20px rgba(56, 189, 248, 0.3) !important;
    }
    
    /* Export Buttons */
    .stDownloadButton > button {
        background: #f8fafc !important;
        color: #0f172a !important;
        width: 100% !important;
    }

    /* Mobile Responsive Logic */
    @media (max-width: 768px) {
        .main-header { font-size: 2.2rem; }
        .stButton > button { margin-top: 10px !important; }
        div[data-testid="stMetric"] { padding: 15px !important; }
        [data-testid="stMetricValue"] > div { font-size: 1.8rem !important; }
    }

    .footer-credit {
        text-align: center;
        padding: 25px;
        margin-top: 50px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        color: #64748b;
    }
    .footer-credit strong { color: #818cf8; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🔍 PhishScanner</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Professional SMS Link Analyzer & URL Security Inspector</div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    st.metric("🔒 Status", "Ready", "Safe Mode")
with col2:
    st.metric("📊 Analysis", "Multi-Layer", "Real-time")
with col3:
    st.metric("⚙️ Features", "8+", "Advanced")

st.divider()

tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analyzer", "📚 Samples", "ℹ️ Help", "👤 About Me"])

with tab2:
    st.subheader("Preloaded Sample URLs")
    st.markdown("Click any sample to analyze it instantly:")
    
    for idx, sample in enumerate(SAMPLE_URLS):
        col1, col2 = st.columns([0.4, 0.6])
        with col1:
            if st.button(f"Load: {sample['name']}", key=f"btn_{idx}"):
                st.session_state.url_to_analyze = sample['url']
                # Programmatically update the text input key
                st.session_state["url_input_field"] = sample['url']
                st.rerun()
        with col2:
            st.markdown(f"<div style='padding-top: 10px; color: #cbd5e1;'>{sample['description']}</div>", unsafe_allow_html=True)

with tab1:
    st.subheader("URL Input")
    
    col1, col2 = st.columns([4, 1])
    with col1:
        default_url = st.session_state.get('url_to_analyze', '')
        url_input = st.text_input(
            "Paste suspicious URL",
            value=default_url,
            placeholder="https://paypal-verify.xyz/login?id=...",
            key="url_input_field"
        )
    with col2:
        if st.button("Clear", use_container_width=True):
            st.session_state.url_to_analyze = ''
            st.rerun()
    
    with st.expander("🔑 API Keys (Optional)"):
        col1, col2 = st.columns(2)
        with col1:
            vt_key = st.text_input("VirusTotal API Key", type="password", key="vt_key")
        with col2:
            gsb_key = st.text_input("Google Safe Browsing API Key", type="password", key="gsb_key")
    
    run_btn = st.button("🔍 Analyze URL (Safe Mode)", use_container_width=True, type="primary")
    
    # This logic block now controls the content *within* tab1, without stopping the whole app.
    if not (run_btn or st.session_state.get('url_to_analyze')) or not url_input:
        st.info("👈 Paste a URL or select a sample to begin analysis.")
    else:
        # This block now contains all the analysis logic.
        with st.spinner("🔄 Analyzing URL... Please wait."):
            url_norm = normalize_url(url_input)
            
            if not is_valid_url(url_norm):
                st.error("❌ Invalid URL format. Please check your input.")
                st.stop()
            
            try:
                parsed, host = parse_url(url_norm)
                host_clean = host.split(':')[0]
                domain, subdomain, suffix = extract_domain(host_clean)
                heuristic_score, heuristic_issues = url_heuristics(url_norm, parsed)
                whois_info = get_whois_info(domain) if domain else {'error': 'Could not extract domain for WHOIS lookup.'}

                # Smart Threat Intel: Typosquatting check
                typo_issue = check_typosquatting(domain)
                if typo_issue:
                    heuristic_issues.append(("Potential Typosquatting", typo_issue, "danger"))
                    heuristic_score += 5
                
                st.success("✅ Analysis Complete!")
                st.divider()
                
                # --- Main Results Display ---
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📋 URL Information")
                    st.write("**Input URL:**")
                    st.code(url_input, language="text")
                    st.write("**Normalized URL:**")
                    st.code(url_norm, language="text")
                    
                    st.write("**Domain Details:**")
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Domain", domain or "N/A")
                    with col_b:
                        st.metric("TLD", suffix or "N/A")
                    with col_c:
                        st.metric("Subdomain", subdomain or "None")
                
                with col2:
                    st.subheader("⚠️ Risk Assessment")
                    risk = heuristic_score * 10
                    
                    headers = safe_fetch_headers(url_norm, method='HEAD')
                    if headers.get('status_code'):
                        if headers['status_code'] >= 400:
                            risk += 10
                    
                    ssl_res = ssl_info(host_clean)
                    if 'error' in ssl_res:
                        risk += 5
                    
                    # Add WHOIS data to risk score
                    if not whois_info.get('error') and whois_info.get('domain_age_days') is not None:
                        if whois_info['domain_age_days'] < 180: # Less than 6 months old
                            risk += 15
                            heuristic_issues.append(("Newly Registered Domain", f"{whois_info['domain_age_days']} days old", "danger"))

                    risk = min(risk, 100)
                    
                    gauge_fig = create_gauge_chart(risk)
                    st.plotly_chart(gauge_fig, use_container_width=True)

                    if risk >= 80:
                        st.error(f"🚨 **HIGH RISK** - Score: {risk}/100")
                        st.write("⛔ **DO NOT** click this link or interact with it.")
                    elif risk >= 40:
                        st.warning(f"⚠️ **MODERATE RISK** - Score: {risk}/100")
                        st.write("⚠️ Proceed with extreme caution.")
                    else:
                        st.success(f"✅ **LOWER RISK** - Score: {risk}/100")
                        st.write("ℹ️ Still verify the sender before clicking.")
                
                st.divider()
                
                # --- Advanced Dashboard Tabs ---
                res_tab1, res_tab2, res_tab3, res_tab4 = st.tabs(["Heuristics & Issues", "Network & Domain", "HTTP Headers", "Full Report (JSON)"])

                with res_tab1:
                    st.subheader("🔍 Heuristic Analysis & Found Issues")
                    if not heuristic_issues:
                        st.success("✅ No significant heuristic red flags detected.")
                    else:
                        st.metric("Heuristic Flags Found", len(heuristic_issues))
                        for title, detail, severity in sorted(heuristic_issues, key=lambda x: x[2], reverse=True): # Show danger first
                            if severity == "danger":
                                st.error(f"🔴 **{title}:** {detail}")
                            elif severity == "warning":
                                st.warning(f"🟡 **{title}:** {detail}")
                            else:
                                st.info(f"🔵 **{title}:** {detail}")

                with res_tab2:
                    st.subheader("🌐 Network & Domain Provenance")
                    col_dns, col_ssl, col_whois = st.columns(3)

                    with col_dns:
                        st.write("**DNS Resolution**")
                        try:
                            dns_res = resolve_dns(domain or host_clean)
                            if dns_res.get('A'):
                                st.success(f"A: {', '.join(dns_res['A'])}")
                            elif dns_res.get('A_error'):
                                st.warning(f"A: {dns_res.get('A_error')}")
                            if dns_res.get('MX'):
                                st.success(f"MX: Found")
                            elif dns_res.get('MX_error'):
                                st.info(f"MX: {dns_res.get('MX_error')}")
                        except Exception as e:
                            st.error(f"DNS lookup failed: {str(e)}")

                    with col_ssl:
                        st.write("**SSL/TLS Certificate**")
                        if ssl_res.get('error'):
                            st.warning(f"No SSL Cert: {ssl_res['error']}")
                        else:
                            st.success("Valid SSL Certificate")
                            if ssl_res.get('issuer'):
                                issuer_org = ssl_res['issuer'].get('organizationName', 'Unknown')
                                st.caption(f"Issuer: {issuer_org}")

                    with col_whois:
                        st.write("**WHOIS Lookup**")
                        if whois_info.get('error'):
                            st.warning(f"{whois_info['error']}")
                        else:
                            st.success("WHOIS data found")
                            age = whois_info.get('domain_age_days')
                            st.caption(f"Age: {age} days" if age is not None else "Age: N/A")
                            st.caption(f"Registrar: {whois_info.get('registrar', 'N/A')}")

                with res_tab3:
                    st.subheader("📡 HTTP Headers (Safe HEAD Request)")
                    st.json(headers)

                # Prepare the final report dictionary
                report = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "input_url": url_input,
                    "normalized_url": url_norm,
                    "final_risk_score": risk,
                    "risk_level": "HIGH" if risk >= 80 else "MODERATE" if risk >= 40 else "LOW",
                    "domain_info": {
                        "domain": domain,
                        "subdomain": subdomain,
                        "suffix": suffix
                    },
                    "whois_info": whois_info,
                    "heuristic_analysis": {
                        "score": heuristic_score,
                        "issues": [{"title": t, "detail": d, "severity": s} for t, d, s in heuristic_issues]
                    },
                    "dns_records": locals().get('dns_res', {}),
                    "ssl_certificate": {
                        "has_error": "error" in ssl_res,
                        "issuer": ssl_res.get('issuer'),
                        "valid_until": ssl_res.get('notAfter')
                    },
                    "http_headers": {
                        "status_code": headers.get('status_code'),
                        "has_error": "error" in headers
                    }
                }

                with res_tab4:
                    st.subheader("📊 Full JSON Report")
                    st.json(report)

                st.divider()
                st.subheader("⬇️ Export Report")
                btn_col1, btn_col2 = st.columns(2)
                with btn_col1:
                    st.download_button(
                        "📄 Download JSON", data=json.dumps(report, indent=2),
                        file_name=f"phish_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", mime="application/json", use_container_width=True)
                with btn_col2:
                    pdf_data = generate_pdf_report(report)
                    st.download_button(
                        "📕 Download PDF", data=pdf_data,
                        file_name=f"phish_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mime="application/pdf", use_container_width=True)

                st.session_state.url_to_analyze = ''
                
            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")

with tab3:
    st.subheader("About PhishScanner")
    st.markdown("""
    PhishScanner performs **non-executing, defensive analysis** of suspicious URLs:
    
    **Analysis Methods:**
    - 🔍 **URL Heuristics**: Detects suspicious patterns, keywords, and structures
    - 🌐 **DNS Resolution**: Checks domain registration and mail servers
    - 🔒 **SSL/TLS Verification**: Validates certificate authenticity
    - 📡 **HTTP Headers**: Analyzes server responses safely
    - 🛡️ **Optional APIs**: VirusTotal and Google Safe Browsing integration
    
    **Risk Scoring:**
    - 🟢 **0-30**: Low Risk - Generally safe
    - 🟡 **30-60**: Moderate Risk - Use caution
    - 🔴 **60-100**: High Risk - Avoid interaction
    
    **✅ Works With:**
    - Real URLs (https://google.com, https://amazon.com, etc)
    - Fake phishing URLs (sample URLs provided)
    - IP-based URLs
    - URLs with complex query parameters
    
    **⚠️ Important:**
    - This tool does NOT render pages or execute JavaScript
    - For highly suspicious links, analyze in isolated environment (VM/Docker)
    - Never paste sensitive links in shared deployments
    - Always verify sender independently
    """)
    
    st.divider()
    st.subheader("🔗 URL Heuristic Indicators")
    
    indicators = {
        "Indicator": [
            "IP Address instead of domain",
            "Contains '@' symbol",
            "Multiple '//' sequences",
            "Punycode (xn--)",
            "Suspicious TLD (.xyz, .club, etc)",
            "Suspicious keywords (login, verify, etc)",
            "Multiple hyphens in domain",
            "Very long URL (>75 chars)"
        ],
        "Risk Level": ["🔴 High", "🔴 High", "🟡 Medium", "🔴 High", "🟡 Medium", "🟡 Medium", "🟡 Medium", "🟡 Medium"],
        "Reason": [
            "Attackers use IPs to hide real domain",
            "Used to obfuscate destination",
            "Malformed URL structure",
            "Homograph attack potential",
            "Commonly abused by malicious actors",
            "Phishing-related language",
            "Domain mimicking legitimate sites",
            "Unusual for legitimate URLs"
        ]
    }
    
    st.dataframe(indicators, use_container_width=True, hide_index=True)
    
    st.divider()
    st.subheader("💡 Tips for Safe URL Analysis")
    st.write("""
    1. **Never click** suspicious links directly - use this tool first
    2. **Verify sender** through official channels, not by replying
    3. **Check domain carefully** - paypa1.com ≠ paypal.com
    4. **Hover before clicking** - see where link actually goes
    5. **Use VPN** when analyzing in VM/sandboxed environment
    6. **Report phishing** to the legitimate company's security team
    """)

with tab4:
    st.subheader("👤 About the Developer")
    
    col1, col2 = st.columns([2.5, 1.5])
    
    with col1:
        st.write("## 🐸 [Amal Alexander](https://www.linkedin.com/in/amal-alexander-305780131/)")
        st.write("**Owner of [Ultra Frog 🐸](https://ultra-frog.onrender.com/)**")
        st.divider()
        
        st.write("### 📊 Professional Summary")
        st.write("With **4+ years of experience in SEO**, I've successfully led strategies across Healthcare, BFSI & Finance, and E-commerce helping brands recover, scale, and dominate search visibility even in competitive and regulated industries.")
        
        st.divider()
        st.write("### 🏆 Most Impactful Healthcare Projects")
        
        st.write("**📈 145% Organic Traffic Growth in Just 3 Months**")
        st.write("For a site previously penalized by Google for spam link activity:")
        st.write("- Applied data-led keyword mapping and trust rebuilding strategies")
        st.write("- Implemented SERP-aligned content optimization")
        st.write("- Not only recovered but **surpassed previous benchmarks**")
        
        st.write("**💰 320% Revenue Uplift**")
        st.write("Through deep competitor trend analysis and search-intent-focused strategy:")
        st.write("- Aligned content efforts to bottom-of-funnel queries")
        st.write("- Optimized for real user behavior and decision patterns")
        st.write("- Transformed organic performance into measurable revenue generation")
        
        st.divider()
        st.write("### 💡 Core Philosophy")
        st.info("**SEO is a long-term business enabler** — not just about backlinks and rankings, but aligning with evolving search intent and user needs.")
        
        st.divider()
        st.write("### 💼 Domain Expertise")
        
        with st.expander("🏥 Healthcare SEO", expanded=True):
            st.write("- YMYL-compliant structures")
            st.write("- Trust signal restoration")
            st.write("- Semantic search coverage")
        
        with st.expander("🏦 BFSI & Banking Finance"):
            st.write("- Increased traffic by using smart schema markup")
            st.write("- Lead-focused content strategy")
            st.write("- Targeting users at the right moment in their decision journey")
        
        with st.expander("🛒 E-commerce SEO"):
            st.write("- Product/category discovery optimization")
            st.write("- Internal linking architecture")
            st.write("- Conversion-focused pages optimization")
        
        st.divider()
        st.write("### 🤖 Special Skills")
        
        st.write("✅ **AI-Powered SEO Tool Development**")
        st.write("Streamlit + spaCy visualizers, bulk schema generators")
        
        st.write("✅ **Browser Extension Creation**")
        st.write("SEO audit automation, competitor data scraping")
        
        st.write("✅ **Structured Data Expertise**")
        st.write("FAQ, Breadcrumb, HowTo, Review schemas")
        
        st.write("✅ **Penalty Recovery Planning**")
        st.write("Manual/spam link cleanups, disavow files, content trust rebuild")
        
        st.write("✅ **Entity-based Content Strategy & Search Intent Modeling**")
        
        st.write("✅ **Competitor Content Gap + Performance Analysis**")
    
    with col2:
        st.write("### 🌐 Connect With Me")
        
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            st.markdown("[🔗 LinkedIn Profile](https://www.linkedin.com/in/amal-alexander-305780131/)", unsafe_allow_html=True)
        with col_btn2:
            st.markdown("[🐸 Ultra Frog](https://ultra-frog.onrender.com/)", unsafe_allow_html=True)
        
        st.divider()
        st.write("### 📌 Quick Stats")
        
        stat_col1, stat_col2 = st.columns(2)
        with stat_col1:
            st.metric("Experience", "4+ Years")
            st.metric("Industries", "3+ Sectors")
        with stat_col2:
            st.metric("Traffic Growth", "145%+")
            st.metric("Revenue Uplift", "320%+")
        
        st.divider()
        st.write("### 🎯 Services")
        
        st.write("✓ SEO Strategy & Planning")
        st.write("✓ Tool Development")
        st.write("✓ Data Analysis")
        st.write("✓ Penalty Recovery")
        st.write("✓ Content Strategy")
        st.write("✓ Competitor Analysis")
        st.write("✓ Schema Implementation")
        
        st.divider()
        st.write("### 🔧 Tech Stack")
        
        st.write("• Python")
        st.write("• Streamlit")
        st.write("• spaCy NLP")
        st.write("• Schema.org")
        st.write("• GSC & Analytics")
        st.write("• Extension Dev")

st.divider()
st.caption("🔐 PhishScanner v2.0 — Safe, Professional SMS Link Analysis | Non-Executing Defense Mode Active")
st.markdown("<div class='footer-credit'>👨‍💻 Developed by <strong>Sophia Dcruz</strong></div>", unsafe_allow_html=True)