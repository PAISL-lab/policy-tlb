from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RESOURCE_DIR = PACKAGE_ROOT / "resources"


def resource_path(name: str) -> Path:
    return RESOURCE_DIR / name


def load_stylesheet() -> str:
    path = resource_path("style.qss")
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")
