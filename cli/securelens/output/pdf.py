from fpdf import FPDF
import datetime
from typing import Optional

def sanitize_text(text: Optional[str]) -> str:
    if not text:
        return ""
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "-",
        "\u2022": "*",
        "\u2026": "...",
        "\u2713": "OK",
        "\u2714": "OK",
        "\u2715": "X",
        "\u2717": "X",
        "\u2718": "X",
        "\u26a0": "!",
        "\u25b6": ">",
        "\u25c0": "<",
        "\u25b2": "^",
        "\u25bc": "v",
        "\u25ae": "|",
        "\u2588": "#",
        "\u2591": ".",
        "\u2592": ":",
        "\u2593": "#",
        "`": "'",
    }
    for orig, rep in replacements.items():
        text = text.replace(orig, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")

class SecureLensPDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def export_code_pdf(result, output_path: str) -> str:
    """
    Generates a PDF report for a local codebase scan.
    """
    pdf = SecureLensPDF()
    pdf.add_page()

    # Header section
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 15, "SecureLens AI - Codebase Security Audit", new_x="LMARGIN", new_y="NEXT", align="C")
    
    # Metadata
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 8, sanitize_text(f"Target Path: {result.target}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Scan Time: {now_str}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, sanitize_text(f"Security Score: {result.score}/100 (Grade: {result.grade})"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Executive Summary Section
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, " Executive Summary", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)
    summary_text = result.ai_summary or f"A static patterns analysis was performed on the codebase. Out of the files discovered, {len(result.vulnerabilities)} potential security vulnerabilities were reported."
    pdf.multi_cell(0, 5, sanitize_text(summary_text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    # Files Scanned Section
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 10, " Files Analyzed", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)
    files_list = ", ".join(result.files_triaged[:15])
    if len(result.files_triaged) > 15:
        files_list += f", and {len(result.files_triaged) - 15} more"
    pdf.multi_cell(0, 5, sanitize_text(files_list or "No files selected."), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    # Issues Findings Section
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 10, " Security Findings", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(5)

    if not result.vulnerabilities:
        pdf.set_font("helvetica", "I", 11)
        pdf.set_text_color(0, 100, 0)
        pdf.cell(0, 10, "No security vulnerabilities were identified in the scanned files.", new_x="LMARGIN", new_y="NEXT")
    else:
        for idx, v in enumerate(result.vulnerabilities, 1):
            severity = v.severity
            pdf.set_font("helvetica", "B", 11)
            
            # Severity color coding
            if severity == "Critical": pdf.set_text_color(200, 0, 0)
            elif severity == "High": pdf.set_text_color(255, 69, 0)
            elif severity == "Medium": pdf.set_text_color(218, 165, 32)
            else: pdf.set_text_color(0, 100, 0)
            
            line_str = f" [Line {v.line_number}]" if v.line_number else ""
            pdf.cell(0, 8, sanitize_text(f"{idx}. {severity}: {v.issue}{line_str}"), new_x="LMARGIN", new_y="NEXT")
            
            # Details
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(20, 6, "File:", border=0)
            pdf.set_font("helvetica", "", 9)
            pdf.cell(0, 6, sanitize_text(v.file_path), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(0, 6, "Explanation:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 9)
            pdf.multi_cell(0, 4.5, sanitize_text(v.explanation), new_x="LMARGIN", new_y="NEXT")
            
            if v.suggested_fix:
                pdf.set_font("helvetica", "B", 9)
                pdf.cell(0, 6, "Suggested Fix:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("courier", "", 8.5)
                pdf.set_fill_color(245, 245, 245)
                pdf.multi_cell(0, 4.5, sanitize_text(v.suggested_fix), fill=True, new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(4)
            pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

    pdf.output(output_path)
    return output_path


def export_web_pdf(result, output_path: str) -> str:
    """
    Generates a PDF report for a live URL scan.
    """
    pdf = SecureLensPDF()
    pdf.add_page()

    # Header section
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 15, "SecureLens AI - Website Security Audit", new_x="LMARGIN", new_y="NEXT", align="C")
    
    # Metadata
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 8, sanitize_text(f"Target URL: {result.url}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Scan Time: {now_str}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, sanitize_text(f"Security Score: {result.score}/100 (Grade: {result.grade})"), new_x="LMARGIN", new_y="NEXT")
    if result.ssl_expiry_days is not None:
        pdf.cell(0, 8, f"SSL Expiry: {result.ssl_expiry_days} days left", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Executive Summary Section
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, " Executive Summary", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)
    summary_text = result.ai_summary or f"An automated live security audit was performed on {result.url}. Out of the layers checked, {len(result.issues)} potential issues were flagged."
    pdf.multi_cell(0, 5, sanitize_text(summary_text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    # Issues Section
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 10, " Discovered Security Issues", new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(5)

    if not result.issues:
        pdf.set_font("helvetica", "I", 11)
        pdf.set_text_color(0, 100, 0)
        pdf.cell(0, 10, "No security issues were identified during the URL scan.", new_x="LMARGIN", new_y="NEXT")
    else:
        for idx, i in enumerate(result.issues, 1):
            severity = i.severity
            pdf.set_font("helvetica", "B", 11)
            
            # Severity color coding
            if severity == "Critical": pdf.set_text_color(200, 0, 0)
            elif severity == "Warning": pdf.set_text_color(218, 165, 32)
            else: pdf.set_text_color(0, 100, 0)
            
            pdf.cell(0, 8, sanitize_text(f"{idx}. {severity}: {i.issue}"), new_x="LMARGIN", new_y="NEXT")
            
            # Details
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(20, 6, "Layer:", border=0)
            pdf.set_font("helvetica", "", 9)
            pdf.cell(0, 6, sanitize_text(i.layer), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(0, 6, "Remediation / Fix:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("courier", "", 8.5)
            pdf.set_fill_color(245, 245, 245)
            pdf.multi_cell(0, 4.5, sanitize_text(i.fix), fill=True, new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(4)
            pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

    pdf.output(output_path)
    return output_path
