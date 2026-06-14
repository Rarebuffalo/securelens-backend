import pytest
from pathlib import Path
from securelens.scanners import LocalScanResult, VulnerabilityFinding
from securelens.output.exporters import save_pdf

@pytest.fixture(autouse=True)
def setup_db():
    # Override the database autouse fixture because these tests do not touch the DB.
    pass

def test_export_code_pdf_compiles(tmp_path):
    # Setup mock result
    findings = [
        VulnerabilityFinding(
            file_path="app.py",
            severity="Critical",
            issue="Hardcoded Secret Key with unicode ’smart’ quotes",
            explanation="Exposing secret key inside app.py • vulnerable to attacks.",
            suggested_fix="Load key from environment: jwt_secret = Field(default=\"\") \u25b6 check it.",
            line_number=5
        ),
        VulnerabilityFinding(
            file_path="db.py",
            severity="High",
            issue="Raw SQL Statement \u2717 check fail",
            explanation="SQL injection inside db.py.",
            suggested_fix="Use parameterized queries",
            line_number=20
        )
    ]
    
    result = LocalScanResult(
        target="/home/user/project",
        total_files_found=10,
        files_triaged=["app.py", "db.py"],
        vulnerabilities=findings,
        ai_summary="This is a dummy AI report summary describing security posture with check \u2713 and block \u2588."
    )
    result.compute_score()
    
    # Save to temp PDF file
    out_file = tmp_path / "report.pdf"
    
    from securelens.output.pdf import export_code_pdf
    export_code_pdf(result, str(out_file))
    
    assert out_file.exists()
    assert out_file.stat().st_size > 1000  # should be non-empty PDF file
