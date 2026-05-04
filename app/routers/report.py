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
from app.models.code_scan import CodeScanResult
from app.models.user import User

router = APIRouter(tags=["report"])


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


def _generate_code_csv(scan: CodeScanResult) -> io.StringIO:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["SecureLens AI - Repository Security Report"])
    writer.writerow(["Repository", scan.repo_url])
    writer.writerow(["Date", scan.created_at.strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow([])

    writer.writerow(["Executive Summary"])
    writer.writerow([scan.summary])
    writer.writerow([])

    writer.writerow(["File Path", "Severity", "Issue", "Line", "Explanation", "Suggested Fix"])
    for i in scan.issues:
        writer.writerow([
            i.get("file_path"),
            i.get("severity"),
            i.get("issue"),
            i.get("line_number", "N/A"),
            i.get("explanation"),
            i.get("suggested_fix"),
        ])

    output.seek(0)
    return output


def _generate_code_pdf(scan: CodeScanResult) -> io.BytesIO:
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 15, "SecureLens AI - Repository Security Report", new_x="LMARGIN", new_y="NEXT", align="C")
    
    # Metadata
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, f"Repository: {scan.repo_url}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Scan Date: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Summary Section
    pdf.set_font("helvetica", "B", 14)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font("helvetica", "", 11)
    pdf.ln(2)
    pdf.multi_cell(0, 6, scan.summary)
    pdf.ln(10)

    # Issues Section
    pdf.set_font("helvetica", "B", 14)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, "Security Findings", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(5)

    if not scan.issues:
        pdf.set_font("helvetica", "I", 11)
        pdf.cell(0, 10, "No security vulnerabilities were identified in the scanned files.", new_x="LMARGIN", new_y="NEXT")
    else:
        for i in scan.issues:
            # Issue Title & Severity
            severity = i.get("severity", "Medium")
            pdf.set_font("helvetica", "B", 12)
            
            # Severity color coding
            if severity == "Critical": pdf.set_text_color(200, 0, 0)
            elif severity == "High": pdf.set_text_color(255, 69, 0)
            elif severity == "Medium": pdf.set_text_color(218, 165, 32)
            else: pdf.set_text_color(0, 100, 0)
            
            line_str = f" [Line {i.get('line_number')}]" if i.get('line_number') else ""
            pdf.cell(0, 8, f"{severity}: {i.get('issue')}{line_str}", new_x="LMARGIN", new_y="NEXT")
            
            # Details
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(30, 6, "File:", border=0)
            pdf.set_font("helvetica", "", 10)
            pdf.cell(0, 6, i.get("file_path"), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 6, "Explanation:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 10)
            pdf.multi_cell(0, 5, i.get("explanation"))
            
            if i.get("suggested_fix"):
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 6, "Suggested Fix:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("courier", "", 9)
                pdf.set_fill_color(245, 245, 245)
                pdf.multi_cell(0, 5, i.get("suggested_fix"), fill=True)
            
            pdf.ln(6)
            pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

    pdf_bytes = pdf.output()
    return io.BytesIO(pdf_bytes)


@router.get("/scans/{scan_id}/export/csv")
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


@router.get("/scans/{scan_id}/export/pdf")
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


@router.get("/code-scans/{scan_id}/export/csv")
async def export_code_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CodeScanResult).where(
            CodeScanResult.id == scan_id, 
            CodeScanResult.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code scan not found")

    csv_data = _generate_code_csv(scan)
    response = StreamingResponse(iter([csv_data.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=code_scan_{scan_id}.csv"
    return response


@router.get("/code-scans/{scan_id}/export/pdf")
async def export_code_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CodeScanResult).where(
            CodeScanResult.id == scan_id, 
            CodeScanResult.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code scan not found")

    try:
        pdf_data = _generate_code_pdf(scan)
        response = StreamingResponse(pdf_data, media_type="application/pdf")
        response.headers["Content-Disposition"] = f"attachment; filename=code_scan_{scan_id}.pdf"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation failed: {str(e)}")
