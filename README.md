# AuthLeak

An automated, high-speed web application reconnaissance and vulnerability scanner tailored for bug bounty hunters. Built entirely in Python, FastAPI, and Tailwind CSS to deliver rapid, zero-cost client-side scanning directly to a local web dashboard.

## 🚀 Core Features
*   **Exposed Secret Analyzer:** High-speed static analysis engine that extracts client-side JavaScript assets and scans them using optimized regex patterns to detect leaked API keys, tokens, and endpoints.
*   **TokenSwap Engine:** An automated active fuzzing engine designed to detect high-paying Broken Access Control and IDOR (Insecure Direct Object Reference) flaws by swapping authentication states between user sessions.
*   **Instant PoC Generator:** Every confirmed vulnerability automatically outputs copy-pasteable `cURL` commands and native Python `requests` scripts for immediate reproduction.
*   **Remediation Mapping:** Provides developers and hunters with explicit Markdown-formatted engineering fixes to securely remediate discovered vulnerabilities.

## 🛠️ Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com
   cd AuthLeak
   ```
2. Install dependencies:
   ```bash
   pip install fastapi uvicorn httpx beautifulsoup4
   ```
3. Run the local dashboard:
   ```bash
   uvicorn main:app --reload
   ```
   Open `http://localhost:8000` in your browser.
