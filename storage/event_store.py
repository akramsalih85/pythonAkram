"""Stockage transactionnel des événements SSH dans SQLite."""

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from logger_config import get_module_logger
from pipeline.orchestrator import LogEvent

_LOGGER = get_module_logger(__name__)


class EventStore:
    """Enregistre les événements parsés dans une base SQLite."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)

    def _connect(self) -> sqlite3.Connection:
        """Prépare le dossier de la base puis ouvre la connexion."""
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database_path, timeout=10)
            connection.row_factory = sqlite3.Row
            return connection
        except (OSError, sqlite3.Error):
            _LOGGER.exception("Ouverture impossible de la base %s", self.database_path)
            raise

    def save_events(self, events: Iterable[LogEvent]) -> int:
        """Remplace le jeu d'événements par la dernière analyse complète."""
        event_list = list(events)
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_file TEXT NOT NULL,
                        line_number INTEGER NOT NULL,
                        ip_address TEXT NOT NULL,
                        username TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('Success', 'Failed', 'Invalid')
                        ),
                        country TEXT NOT NULL,
                        occurrences INTEGER NOT NULL CHECK (occurrences > 0)
                    )
                    """
                )
                connection.execute("DELETE FROM events")
                connection.executemany(
                    """
                    INSERT INTO events (
                        timestamp, source_file, line_number, ip_address,
                        username, status, country, occurrences
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            event.timestamp.isoformat(sep=" "),
                            event.source_file,
                            event.line_number,
                            event.ip_address,
                            event.username,
                            event.status,
                            event.country,
                            event.occurrences,
                        )
                        for event in event_list
                    ],
                )
            _LOGGER.info(
                "Base %s mise à jour : %d événements",
                self.database_path,
                len(event_list),
            )
            return len(event_list)
        except (OSError, sqlite3.Error):
            _LOGGER.exception("Écriture impossible dans la base %s", self.database_path)
            raise
        finally:
            connection.close()

    def fetch_events(self) -> list[dict[str, Any]]:
        """Lit les événements pour les agrégations du tableau de bord."""
        connection = self._connect()
        try:
            with connection:
                rows = connection.execute(
                    """
                    SELECT timestamp, source_file, line_number, ip_address,
                           username, status, country, occurrences
                    FROM events
                    ORDER BY timestamp, source_file, line_number
                    """
                ).fetchall()
            return [dict(row) for row in rows]
        except (OSError, sqlite3.Error):
            _LOGGER.exception("Lecture impossible dans la base %s", self.database_path)
            raise
        finally:
            connection.close()

