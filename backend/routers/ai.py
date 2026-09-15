"""
FastAPI Router — AI Analyst Chat Operations
"""

from fastapi import APIRouter, HTTPException, Depends
from database.models import ChatRequest
from database.db import get_scan, save_chat_message, get_chat_history
from ai.groq_service import chat_with_ai_analyst
from auth.auth import get_current_user

router = APIRouter(prefix="", tags=["AI Analyst Chat"])


@router.post("/chat")
@router.post("/api/chat")
async def send_chat_message(req: ChatRequest, user_id: str = Depends(get_current_user)):
    """Send user message to AI Analyst and save to database."""
    scan_id = req.scan_id
    user_text = req.message.strip()

    if not user_text:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Fetch scan context
    scan_data = await get_scan(scan_id)

    # Get conversation history
    history = await get_chat_history(scan_id)

    # Save user message
    user_msg_obj = await save_chat_message(scan_id, "user", user_text)

    # Generate response from Groq AI Analyst
    ai_text = await chat_with_ai_analyst(scan_data, history, user_text)

    # Save AI response
    ai_msg_obj = await save_chat_message(scan_id, "ai", ai_text)

    return {
        "user_message": user_msg_obj,
        "ai_response": ai_msg_obj,
    }


@router.get("/chat/{scan_id}")
@router.get("/api/chat/{scan_id}")
async def get_scan_chat_history(scan_id: str, user_id: str = Depends(get_current_user)):
    """Get conversation history for a given scan."""
    history = await get_chat_history(scan_id)
    return history
