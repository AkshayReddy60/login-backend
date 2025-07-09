from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr, constr, validator
import rsa
import os
import jwt
import datetime
import psycopg2
import psycopg2.extras
from psycopg2.errors import UniqueViolation
import re
from datetime import date, time

# === JWT Config ===
JWT_SECRET = "Akshay"
JWT_ALGORITHM = "HS256"

# === RSA Keys Setup ===
KEY_DIR = "keys"
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public.pem")
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private.pem")

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

if os.path.exists(PUBLIC_KEY_FILE) and os.path.exists(PRIVATE_KEY_FILE):
    with open(PUBLIC_KEY_FILE, "rb") as pub_file, open(PRIVATE_KEY_FILE, "rb") as priv_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
else:
    public_key, private_key = rsa.newkeys(512)
    with open(PUBLIC_KEY_FILE, "wb") as pub_file, open(PRIVATE_KEY_FILE, "wb") as priv_file:
        pub_file.write(public_key.save_pkcs1())
        priv_file.write(private_key.save_pkcs1())

# === FastAPI App ===
app = FastAPI()

# === PostgreSQL Config ===
db_config = {
    "dbname": "School",
    "user": "postgres",
    "password": "Akshay@2003",
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    return psycopg2.connect(**db_config, cursor_factory=psycopg2.extras.RealDictCursor)

# === Table Creation ===
@app.on_event("startup")
def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terms (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS classes (
                id SERIAL PRIMARY KEY,
                term_id INTEGER REFERENCES terms(id) ON DELETE CASCADE,
                class_name VARCHAR(100) NOT NULL,
                start_time TIME NOT NULL,
                end_time TIME NOT NULL
            );
        """)
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# === Pydantic Models ===
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: constr(min_length=8)

    @validator('email')
    def validate_email(cls, v):
        allowed_domains = ["@gmail.com", "@outlook.com", "@yahoo.com"]
        if not any(v.endswith(domain) for domain in allowed_domains):
            raise ValueError("Email must end with @gmail.com, @outlook.com or @yahoo.com")
        return v

    @validator('password')
    def strong_password(cls, v):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, v):
            raise ValueError("Password must include uppercase, lowercase, digit, and special character")
        return v

class UserLogin(BaseModel):
    identifier: str
    password: str

class TermCreate(BaseModel):
    name: str
    start_date: date
    end_date: date

class ClassCreate(BaseModel):
    term_id: int
    class_name: str
    start_time: time
    end_time: time

# === Encryption and JWT ===
def encrypt_password(password: str) -> str:
    return rsa.encrypt(password.encode(), public_key).hex()

def decrypt_password(encrypted: str) -> str:
    try:
        return rsa.decrypt(bytes.fromhex(encrypted), private_key).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")

def create_jwt_token(user_id: int, username: str) -> str:
    payload = {
        "sub": username,
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(token: str = Header(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"user_id": payload["user_id"], "username": payload["sub"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# === Routes ===
@app.post("/register/")
def register(user: UserCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        encrypted_pw = encrypt_password(user.password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id",
            (user.username, user.email, encrypted_pw)
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()
        return {"message": "User registered", "user_id": user_id}
    except UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Username or Email already exists")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.post("/signin/")
def signin(user: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password FROM users WHERE username = %s OR email = %s",
                   (user.identifier, user.identifier))
    data = cursor.fetchone()
    cursor.close()
    conn.close()

    if not data or decrypt_password(data["password"]) != user.password:
        raise HTTPException(status_code=401, detail="Invalid username/email or password")

    token = create_jwt_token(data["id"], data["username"])
    return {"message": "Login successful", "token": token, "username": data["username"]}

@app.post("/terms/")
def create_term(term: TermCreate, user=Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO terms (user_id, name, start_date, end_date) VALUES (%s, %s, %s, %s) RETURNING id",
            (user["user_id"], term.name, term.start_date, term.end_date)
        )
        term_id = cursor.fetchone()["id"]
        conn.commit()
        return {"message": "Term created", "term_id": term_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.post("/classes/")
def create_class(cls: ClassCreate, user=Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM terms WHERE id = %s AND user_id = %s", (cls.term_id, user["user_id"]))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Term not found or not authorized")

        cursor.execute(
            "INSERT INTO classes (term_id, class_name, start_time, end_time) VALUES (%s, %s, %s, %s) RETURNING id",
            (cls.term_id, cls.class_name, cls.start_time, cls.end_time)
        )
        class_id = cursor.fetchone()["id"]
        conn.commit()
        return {"message": "Class created", "class_id": class_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()
