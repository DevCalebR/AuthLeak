# target_vulnerable_app.py
from fastapi import FastAPI, Header, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
    <head><title>Mock Login Portal</title></head>
    <body style="background:#111; color:#fff; font-family:sans-serif; text-align:center; padding-top:100px;">
        <h2>🔐 Target Auth Portal (Staging)</h2>
        <form action="/login" method="POST" style="display:inline-block; background:#222; padding:20px; border-radius:8px;">
            <input type="text" name="username" placeholder="Username" required style="padding:8px; margin:5px;"><br>
            <input type="password" name="password" placeholder="Password" required style="padding:8px; margin:5px;"><br>
            <button type="submit" style="padding:8px 20px; background:#007bff; color:#fff; border:none; border-radius:4px; margin-top:10px;">Login</button>
        </form>
    </body>
    </html>
    """

@app.post("/login")
async def handle_login(username: str = Form(...)):
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="session_token", value=f"MOCK_SESSION_JWT_FOR_{username.upper()}")
    return response

@app.get("/static/app.js", response_class=HTMLResponse)
async def mock_js_file():
    return """
console.log("App Initialized...");
const googleApiKey = "AIzaSyAz1234567890O_FakeGoogleTokenKeyXYZ";

fetch("/api/v1/invoice/123")
    .then(response => response.json())
    .then(data => console.log("Invoice response:", data))
    .catch(error => console.error("Invoice request failed:", error));
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return '<html><head><script src="/static/app.js"></script></head><body style="background:#111; color:#fff;"><h1>Welcome to Authenticated Dashboard</h1></body></html>'

@app.api_route("/api/v1/invoice/{invoice_id}", methods=["GET", "POST"])
async def get_invoice(invoice_id: str, cookie: str = Header(None)):
    if not cookie or "session_token" not in cookie.lower():
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"owner": "user_victim", "data": "CONFIDENTIAL: SSN 000-12-3456 | Invoice Total: $54,000"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000)

