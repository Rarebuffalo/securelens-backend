import pytest
from fastapi import HTTPException

from app.utils.validators import validate_url


def test_valid_https_url():
    result = validate_url("https://example.com")
    assert result == "https://example.com"


def test_valid_http_url():
    result = validate_url("http://example.com")
    assert result == "http://example.com"


def test_rejects_ftp_scheme():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("ftp://example.com")
    assert exc_info.value.status_code == 400


def test_rejects_no_scheme():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("example.com")
    assert exc_info.value.status_code == 400


def test_rejects_localhost():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("http://localhost")
    assert exc_info.value.status_code == 400


def test_rejects_private_ip():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("http://192.168.1.1")
    assert exc_info.value.status_code == 400


def test_rejects_loopback():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("http://127.0.0.1")
    assert exc_info.value.status_code == 400


def test_rejects_unresolvable_host():
    with pytest.raises(HTTPException) as exc_info:
        validate_url("http://this-domain-does-not-exist-xyz123.com")
    assert exc_info.value.status_code == 400
