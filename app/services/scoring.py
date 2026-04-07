from app.schemas.scan import Issue, LayerStatus

SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 15,
    "Warning": 5,
    "Info": 2,
}

LAYER_NAMES = [
    "Transport Layer",
    "SSL/TLS Layer",
    "Server Config Layer",
    "Cookie Security",
    "Exposure Layer",
]


def calculate_score(issues: list[Issue]) -> int:
    score = 100
    for issue in issues:
        score -= SEVERITY_WEIGHTS.get(issue.severity, 0)
    return max(score, 0)


def calculate_layer_statuses(issues: list[Issue]) -> dict[str, LayerStatus]:
    layers: dict[str, LayerStatus] = {
        name: LayerStatus(issues=0, status="green") for name in LAYER_NAMES
    }

    for issue in issues:
        if issue.layer in layers:
            layers[issue.layer].issues += 1

    for layer in layers.values():
        if layer.issues == 0:
            layer.status = "green"
        elif layer.issues < 3:
            layer.status = "yellow"
        else:
            layer.status = "red"

    return layers
