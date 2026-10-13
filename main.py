import os
import sqlite3
import httpx
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse

app = FastAPI()

# --- CONFIGURATION ---
# Set these in your environment variables on Railway / Hugging Face
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "https://api.your-secret-china-source.com/v1/chat/completions")
UPSTREAM_KEY = os.getenv("UPSTREAM_KEY", "your_secret_upstream_key_here")
ADMIN_KEY = os.getenv("ADMIN_KEY", "your_secret_admin_password") # Used to generate keys for others

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

# --- DATABASE SETUP ---
def init_db():
    # Creates a local database file to store user keys and token counts
    conn = sqlite3.connect("proxy.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (api_key TEXT PRIMARY KEY, tokens_used INTEGER)''')
    conn.commit()
    conn.close()

init_db()

# --- AUTHENTICATION ---
def get_api_key(header: str = Security(api_key_header)):
    if not header:
        raise HTTPException(status_code=401, detail="Missing API Key")
    
    # Extract the key from the "Bearer <key>" format
    key = header.replace("Bearer ", "").strip()
    
    conn = sqlite3.connect("proxy.db")
    c = conn.cursor()
    c.execute("SELECT tokens_used FROM users WHERE api_key=?", (key,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Invalid custom API Key")
    return key

# --- THE PROXY ENDPOINT ---
@app.post("/v1/chat/completions")
async def chat_completions(request: Request, user_key: str = Security(get_api_key)):
    # 1. Get the user's payload
    body = await request.json()
    
    # 2. Prepare headers with YOUR secret key so the upstream provider accepts it
    headers = {
        "Authorization": f"Bearer {UPSTREAM_KEY}",
        "Content-Type": "application/json"
    }

    # 3. Forward the request to the secret proxy
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(UPSTREAM_URL, json=body, headers=headers, timeout=120.0)
            response.raise_for_status()
            data = response.json()
            
            # 4. Extract token usage from the response (Standard OpenAI API format)
            tokens = data.get("usage", {}).get("total_tokens", 0)
            
            if tokens > 0:
                # Update the database with the user's token usage
                conn = sqlite3.connect("proxy.db")
                c = conn.cursor()
                c.execute("UPDATE users SET tokens_used = tokens_used + ? WHERE api_key = ?", (tokens, user_key))
                conn.commit()
                conn.close()

            # 5. Return the response to the user
            return JSONResponse(content=data)
            
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail="Upstream provider error")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

# --- ADMIN ENDPOINTS (To manage your users) ---
@app.post("/admin/create_key")
def create_key(new_key: str, admin_auth: str = Security(api_key_header)):
    if admin_auth != f"Bearer {ADMIN_KEY}":
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    conn = sqlite3.connect("proxy.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (api_key, tokens_used) VALUES (?, 0)", (new_key,))
        conn.commit()
    except sqlite3.IntegrityError:
        return {"error": "That key already exists"}
    finally:
        conn.close()
    return {"message": "Key created successfully", "key": new_key}

@app.get("/admin/stats")
def get_stats(admin_auth: str = Security(api_key_header)):
    if admin_auth != f"Bearer {ADMIN_KEY}":
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    conn = sqlite3.connect("proxy.db")
    c = conn.cursor()
    c.execute("SELECT api_key, tokens_used FROM users")
    rows = c.fetchall()
    conn.close()
    
    return {"users": [{"api_key": r[0], "tokens_used": r[1]} for r in rows]}
