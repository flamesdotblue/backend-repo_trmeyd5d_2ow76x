import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import Account, Session, Article

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Newsly AI Backend Running"}

# ---------------------- Auth Helpers ----------------------
class SignUpReq(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class SignInReq(BaseModel):
    email: EmailStr
    password: str

class AuthResp(BaseModel):
    token: str
    email: EmailStr
    name: Optional[str] = None

COLL_ACCOUNT = "account"
COLL_SESSION = "session"
COLL_ARTICLE = "article"


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def get_account_by_email(email: str) -> Optional[dict]:
    res = db[COLL_ACCOUNT].find_one({"email": email})
    return res


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    session = Session(user_id=user_id, token=token, expires_at=expires_at)
    create_document(COLL_SESSION, session)
    return token


@app.post("/auth/signup", response_model=AuthResp)
def signup(payload: SignUpReq):
    existing = get_account_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(payload.password, salt)
    acc = Account(email=payload.email, name=payload.name, password_hash=pwd_hash, salt=salt)
    user_id = create_document(COLL_ACCOUNT, acc)
    token = create_session(user_id)
    return AuthResp(token=token, email=payload.email, name=payload.name)


@app.post("/auth/signin", response_model=AuthResp)
def signin(payload: SignInReq):
    acc = get_account_by_email(payload.email)
    if not acc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expected = hash_password(payload.password, acc.get("salt", ""))
    if expected != acc.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(acc.get("_id")))
    return AuthResp(token=token, email=payload.email, name=acc.get("name"))


def require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    sess = db[COLL_SESSION].find_one({"token": token})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db[COLL_ACCOUNT].find_one({"_id": sess["user_id"]}) if isinstance(sess.get("user_id"), str) else db[COLL_ACCOUNT].find_one({"_id": sess.get("user_id")})
    return {"user": user, "token": token}


@app.get("/me")
def me(ctx: dict = Depends(require_user)):
    user = ctx["user"]
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": user.get("email"), "name": user.get("name")}

# ---------------------- Articles ----------------------

SEED_ARTICLES = [
    Article(
        title="Open-source model outperforms on key benchmarks",
        source="Tech Journal",
        time="2h ago",
        tags=["AI", "Open Source"],
        summary="A new community-driven model sets a high-water mark on multiple leaderboards, signaling a shift in AI innovation dynamics.",
        url="#",
    ),
    Article(
        title="Markets rally on strong earnings from cloud leaders",
        source="Market Watch",
        time="4h ago",
        tags=["Markets", "Cloud"],
        summary="Major indices closed higher as hyperscalers reported better-than-expected growth in AI workloads and enterprise migration.",
        url="#",
    ),
    Article(
        title="Regulators unveil guidelines for safe AI deployment",
        source="Policy Daily",
        time="6h ago",
        tags=["Policy", "Safety"],
        summary="The framework emphasizes transparency, evals, and risk management, aiming to balance innovation with responsibility.",
        url="#",
    ),
]


@app.get("/articles")
def list_articles(q: Optional[str] = None) -> List[dict]:
    # Seed if empty
    if db[COLL_ARTICLE].count_documents({}) == 0:
        for a in SEED_ARTICLES:
            create_document(COLL_ARTICLE, a)
    query = {}
    if q:
        regex = {"$regex": q, "$options": "i"}
        query = {"$or": [{"title": regex}, {"summary": regex}, {"tags": regex}, {"source": regex}]}
    docs = get_documents(COLL_ARTICLE, query)
    # Convert ObjectId to string for _id if present
    for d in docs:
        if "_id" in d:
            d["id"] = str(d.pop("_id"))
    return docs


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
