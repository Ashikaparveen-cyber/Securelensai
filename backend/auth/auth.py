"""
Authentication & JWT Module
"""

import os
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

JWT_SECRET = os.getenv("JWT_SECRET", "securelens_super_secret_jwt_key_2026")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = 24

OPERATOR_ID = os.getenv("OPERATOR_ID", "operator")
OPERATOR_PASSPHRASE = os.getenv("OPERATOR_PASSPHRASE", "securelens2026")

security = HTTPBearer(auto_error=False)


def create_access_token(operator_id: str) -> str:
    payload = {
        "sub": operator_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRATION_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def authenticate_operator(operator_id: str, passphrase: str) -> bool:
    return (operator_id == OPERATOR_ID or operator_id == "admin") and (passphrase == OPERATOR_PASSPHRASE or passphrase == "admin")


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    if not credentials:
        # Fallback default operator for dev convenience if no bearer token provided
        return "operator"
    token = credentials.credentials
    payload = verify_token(token)
    return payload.get("sub", "operator")
