from app.schemas.scan import Issue
from app.services.scoring import calculate_layer_statuses, calculate_score


def test_perfect_score_no_issues():
    assert calculate_score([]) == 100


def test_critical_deduction():
    issues = [Issue(issue="Test", severity="Critical", layer="Transport Layer", fix="Fix")]
    assert calculate_score(issues) == 85


def test_warning_deduction():
    issues = [Issue(issue="Test", severity="Warning", layer="Transport Layer", fix="Fix")]
    assert calculate_score(issues) == 95


def test_info_deduction():
    issues = [Issue(issue="Test", severity="Info", layer="Transport Layer", fix="Fix")]
    assert calculate_score(issues) == 98


def test_score_cannot_go_below_zero():
    issues = [Issue(issue=f"Test {i}", severity="Critical", layer="Transport Layer", fix="Fix") for i in range(10)]
    assert calculate_score(issues) == 0


def test_all_layers_present():
    statuses = calculate_layer_statuses([])
    assert "Transport Layer" in statuses
    assert "SSL/TLS Layer" in statuses
    assert "Server Config Layer" in statuses
    assert "Cookie Security" in statuses
    assert "Exposure Layer" in statuses


def test_layer_status_green_when_no_issues():
    statuses = calculate_layer_statuses([])
    for layer in statuses.values():
        assert layer.status == "green"
        assert layer.issues == 0


def test_layer_status_yellow_for_few_issues():
    issues = [
        Issue(issue="Test 1", severity="Warning", layer="SSL/TLS Layer", fix="Fix"),
        Issue(issue="Test 2", severity="Warning", layer="SSL/TLS Layer", fix="Fix"),
    ]
    statuses = calculate_layer_statuses(issues)
    assert statuses["SSL/TLS Layer"].status == "yellow"
    assert statuses["SSL/TLS Layer"].issues == 2


def test_layer_status_red_for_many_issues():
    issues = [
        Issue(issue="Test 1", severity="Warning", layer="Cookie Security", fix="Fix"),
        Issue(issue="Test 2", severity="Warning", layer="Cookie Security", fix="Fix"),
        Issue(issue="Test 3", severity="Critical", layer="Cookie Security", fix="Fix"),
    ]
    statuses = calculate_layer_statuses(issues)
    assert statuses["Cookie Security"].status == "red"
    assert statuses["Cookie Security"].issues == 3
