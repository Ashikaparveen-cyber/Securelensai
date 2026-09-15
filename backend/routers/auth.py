"""
FastAPI Router — Authentication & Session Operations
"""

from fastapi import APIRouter, HTTPException
from database.models import LoginRequest, LoginResponse
from auth.auth import authenticate_operator, create_access_token

router = APIRouter(prefix="", tags=["Authentication"])


@router.post("/auth/login")
@router.post("/api/auth/login")
async def login(req: LoginRequest):
    """Authenticate operator and return access token."""
    if not authenticate_operator(req.operator_id, req.passphrase):
        raise HTTPException(status_code=401, detail="Invalid Operator ID or Passphrase")

    token = create_access_token(req.operator_id)
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        operator_id=req.operator_id,
    )
