"""
Pydantic Request & Response Data Schemas
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class LoginRequest(BaseModel):
    operator_id: str
    passphrase: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    operator_id: str


class ScanRequest(BaseModel):
    url: str
    include_ai: bool = True


class Vulnerability(BaseModel):
    severity: str  # critical, high, medium, low, info
    name: str
    asset: str
    status: str = "open"
    recommendation: Optional[str] = None
    category: Optional[str] = None


class ChatMessage(BaseModel):
    id: Optional[str] = None
    scan_id: str
    sender: str  # "user" or "ai"
    text: str
    timestamp: Optional[str] = None


class ChatRequest(BaseModel):
    scan_id: str
    message: str


class User(BaseModel):
    id: Optional[str] = None
    operator_id: str
    password_hash: str
    created_at: Optional[str] = None
