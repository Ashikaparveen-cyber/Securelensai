"""
FastAPI Router — Report Generation & Download
"""

from fastapi import APIRouter, HTTPException, Response, Depends
from database.db import get_scan
from reports.pdf_generator import generate_scan_pdf_report
from auth.auth import get_current_user

router = APIRouter(prefix="", tags=["Reports"])


@router.get("/reports/{scan_id}/pdf")
@router.get("/api/reports/{scan_id}/pdf")
async def download_pdf_report(scan_id: str, user_id: str = Depends(get_current_user)):
    """Generate and download PDF security assessment report."""
    scan_data = await get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan record not found")

    pdf_bytes = generate_scan_pdf_report(scan_data)
    filename = f"SecureLens_Report_{scan_id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
