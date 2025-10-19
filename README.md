# PhishScanner — Advanced URL Security Inspector

PhishScanner is a powerful Streamlit application designed for the safe, non-executing analysis of suspicious URLs. It provides a multi-layered inspection to help users identify potential phishing, malware, and scam links before clicking them.

**Created by:** [Amal Alexander](https://www.linkedin.com/in/amal-alexander-305780131/)

## Core Features

-   **Advanced Dashboard**: An interactive gauge provides an at-a-glance risk score, with results organized into clear, easy-to-navigate tabs.
-   **URL Heuristics**: Deep analysis of URL structure to detect suspicious patterns, keywords, long strings, and obfuscation techniques.
-   **Smart Threat Intelligence**: Automatically checks for typosquatting and homoglyph attacks against well-known domains.
-   **🌐 Domain WHOIS Lookup**: Fetches domain registration details, including registrar and domain age, to identify newly created, high-risk domains.
-   **Network Analysis**: Performs DNS resolution (A, MX records) and SSL/TLS certificate validation to verify authenticity.
-   **Safe Header Fetch**: Retrieves HTTP headers without rendering any page content or executing scripts.
-   **📦 PDF & JSON Export**: Generates downloadable and shareable summaries of the full analysis.
-   **Optional API Integration**: Enhances detection with VirusTotal and Google Safe Browsing lookups (API keys required).

## How to Run Locally

1.  Create a virtual environment: `python -m venv venv`
2.  Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
3.  Install dependencies: `pip install -r requirements.txt`
4.  Run the app: `streamlit run app.py`

## Notes & Safety

-   The application is designed for **defensive analysis only**. It does not render pages or execute JavaScript.
-   For known malicious links, it is still best practice to run this tool in an isolated environment (like a VM or Docker container).
-   Do not expose a public-facing version of this app without implementing proper authentication and rate-limiting.

## License

MIT 
