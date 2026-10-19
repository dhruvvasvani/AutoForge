"""Model and inference compatibility modules."""

__all__ = ["ASTVulnerabilityClassifier"]


def __getattr__(name: str):
    if name == "ASTVulnerabilityClassifier":
        from .models import ASTVulnerabilityClassifier

        return ASTVulnerabilityClassifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
