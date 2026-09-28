import os
import sqlite3
from typing import Optional, TYPE_CHECKING
from datetime import datetime, timedelta

if TYPE_CHECKING:
    from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, HTTPException, status
    from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
else:
    try:
        from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, HTTPException, status
        from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
        from fastapi.templating import Jinja2Templates
    except ModuleNotFoundError as exc:
        if exc.name != "fastapi":
            raise
        raise RuntimeError(
            "FastAPI is not installed in the active Python environment. "
            "Install the project dependencies (for example: python -m pip install fastapi)."
        ) from exc
from dotenv import load_dotenv
import google.generativeai as genai
from passlib.context import CryptContext
from jose import JWTError, jwt

# Load environment variables
load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretjwtkeypocketsmart2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configure Gemini API
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

# Base Directory Setup for Templates & Static Files (Fixes TemplateNotFound Error)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Ensure static & templates directory exist
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

app = FastAPI(title="PocketSmart AI")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Password Hashing & Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SQLite Database Setup
DB_PATH = os.path.join(BASE_DIR, "pocketsmart.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT NOT NULL,
            date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return {"id": user[0], "username": user[1], "email": user[2]}
    except JWTError:
        return None
    return None

# Routes
@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    user = get_current_user_from_cookie(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="index.html", context={"user": user})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})

@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(password, user[2]):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid username or password"})

    access_token = create_access_token(data={"sub": username})
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html", context={"error": None})

@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    hashed_pwd = get_password_hash(password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)", (username, email, hashed_pwd))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return templates.TemplateResponse(request=request, name="register.html", context={"error": "Username or Email already exists"})
    conn.close()
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_current_user_from_cookie(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, amount, category, date FROM transactions WHERE user_id = ? ORDER BY id DESC", (user["id"],))
    transactions = cursor.fetchall()
    conn.close()

    tx_list = [{"id": t[0], "title": t[1], "amount": t[2], "category": t[3], "date": t[4]} for t in transactions]
    total_spent = sum(t["amount"] for t in tx_list)

    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html", 
        context={"user": user, "transactions": tx_list, "total_spent": total_spent}
    )

@app.post("/add-transaction")
async def add_transaction(request: Request, title: str = Form(...), amount: float = Form(...), category: str = Form(...)):
    user = get_current_user_from_cookie(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO transactions (user_id, title, amount, category, date) VALUES (?, ?, ?, ?, ?)",
                   (user["id"], title, amount, category, date_str))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.post("/api/ai-advice")
async def ai_advice(request: Request):
    user = get_current_user_from_cookie(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if not model:
        return JSONResponse({"advice": "Gemini API key is not configured in .env file."})

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT title, amount, category FROM transactions WHERE user_id = ?", (user["id"],))
    txs = cursor.fetchall()
    conn.close()

    if not txs:
        return JSONResponse({"advice": "Please add some transactions first so PocketSmart AI can analyze your budget!"})

    tx_summary = ", ".join([f"{t[0]} ({t[2]}): ₹{t[1]}" for t in txs])
    prompt = f"Analyze these expenses for user {user['username']}: {tx_summary}. Provide 3 short, actionable financial tips in a friendly tone to save money."

    try:
        response = model.generate_content(prompt)
        return JSONResponse({"advice": response.text})
    except Exception as e:
        return JSONResponse({"advice": f"AI Error: {str(e)}"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)