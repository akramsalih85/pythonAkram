"""Entrée de commande du projet log-analysis."""

import sys
from pathlib import Path


def main() -> int:
    """Délègue à main.py depuis la racine du dépôt."""
    project_root = Path(__file__).resolve().parents[2]
    if not (project_root / "main.py").is_file():
        project_root = Path.cwd()

    root_text = str(project_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)

    from logger_config import get_module_logger

    logger = get_module_logger(__name__)
    if not (project_root / "main.py").is_file():
        logger.error("main.py est introuvable depuis %s", project_root)
        return 1

    from main import main as run_project

    return run_project()


__all__ = ["main"]
