import pytest
from cli.securelens.scanners.patterns import scan_file_content

@pytest.fixture(autouse=True)
def setup_db():
    # Override the database autouse fixture because these tests do not touch the DB.
    pass

def test_hardcoded_aws_key():
    content = 'aws_key = "AKIA1234567890123456"'
    findings = scan_file_content("test.py", content)
    assert len(findings) == 2
    issues = [f.issue for f in findings]
    assert "Hardcoded AWS Access Key ID" in issues
    assert "Hardcoded API/Auth Token" in issues

def test_sql_injection():
    content = 'db.execute(f"select * from users where id = {user_id}")'
    findings = scan_file_content("test.py", content)
    assert len(findings) == 1
    assert findings[0].issue == "Potential SQL Injection"
    assert findings[0].severity == "High"

def test_no_findings():
    content = 'print("hello world")'
    findings = scan_file_content("test.py", content)
    assert len(findings) == 0
