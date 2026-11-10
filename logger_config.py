"""Configuration centralisée des journaux rotatifs du projet."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_DIRECTORY = PROJECT_ROOT / "logs"
LOG_FORMAT = "%(asctime)s|%(levelname)s|%(name)s|%(message)s"
MAX_BYTES = 1_000_000
BACKUP_COUNT = 3


def _filename_for(logger_name: str) -> str:
    """Choisit un fichier de log selon le module appelant."""
    if logger_name in {"main", "__main__"}:
        return "main.log"

    category = logger_name.split(".", maxsplit=1)[0]
    if category in {"ingestion", "processing", "storage", "serving", "pipeline"}:
        return f"{category}.log"
    if category == "logger_config":
        return "logger_config.log"
    return f"{category or 'application'}.log"


def get_module_logger(logger_name: str) -> logging.Logger:
    """Retourne un logger configuré avec un fichier rotatif dédié."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger_name in {"main", "__main__"} and not any(
        getattr(handler, "_project_console_handler", False)
        for handler in logger.handlers
    ):
        console_handler = logging.StreamHandler()
        console_handler._project_console_handler = True  # type: ignore[attr-defined]
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(console_handler)

    log_path = LOG_DIRECTORY / _filename_for(logger_name)
    for handler in logger.handlers:
        if getattr(handler, "_project_log_path", None) == str(log_path):
            return logger

    try:
        LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        handler._project_log_path = str(log_path)  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
    except OSError as error:
        fallback = logging.StreamHandler()
        fallback.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(fallback)
        logger.error("Impossible de créer le journal %s : %s", log_path, error)

    return logger


_LOGGER = get_module_logger(__name__)

