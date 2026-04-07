import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fpdf import FPDF

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.scan import ScanResult
from app.models.user import User

router = APIRouter(prefix="/scans", tags=["report"])


def _generate_csv(scan: ScanResult) -> io.StringIO:
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["SecureLens AI Scan Report"])
    writer.writerow(["URL", scan.url])
    writer.writerow(["Date", scan.created_at.strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["Security Score", scan.security_score])
    writer.writerow([])
    
    writer.writerow(["Issue", "Severity", "Layer", "Fix", "Contextual Severity", "Explanation"])
    for i in scan.issues:
        writer.writerow([
            i.get("issue"),
            i.get("severity"),
            i.get("layer"),
            i.get("fix"),
            i.get("contextual_severity", ""),
            i.get("explanation", ""),
        ])
    
    output.seek(0)
    return output


def _generate_pdf(scan: ScanResult) -> io.BytesIO:
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "SecureLens AI Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 10, f"URL: {scan.url}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Date: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Security Score: {scan.security_score}/100", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(5)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Discovered Issues", new_x="LMARGIN", new_y="NEXT")
    
    for i in scan.issues:
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, f"Issue: {i.get('issue')} [{i.get('severity')}]", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, f"Layer: {i.get('layer')}")
        pdf.multi_cell(0, 6, f"Fix: {i.get('fix')}")
        
        if i.get("explanation"):
            pdf.multi_cell(0, 6, f"AI Context: {i.get('explanation')}")
        pdf.ln(4)
        
    pdf_bytes = pdf.output()
    return io.BytesIO(pdf_bytes)


@router.get("/{scan_id}/export/csv")
async def export_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id, ScanResult.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    csv_data = _generate_csv(scan)
    response = StreamingResponse(iter([csv_data.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=scan_{scan_id}.csv"
    return response


@router.get("/{scan_id}/export/pdf")
async def export_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id, ScanResult.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    try:
        pdf_data = _generate_pdf(scan)
        response = StreamingResponse(pdf_data, media_type="application/pdf")
        response.headers["Content-Disposition"] = f"attachment; filename=scan_{scan_id}.pdf"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation failed: {str(e)}")
