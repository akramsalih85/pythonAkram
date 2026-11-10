"""Lecture, analyse et enrichissement des journaux SSH."""

import gzip
import ipaddress
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import requests

from logger_config import get_module_logger
from processing import extract_transforme

_LOGGER = get_module_logger(__name__)
_INGESTION_LOGGER = get_module_logger("ingestion.adapter")
_PROCESSING_LOGGER = get_module_logger("processing.adapter")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s*(?P<body>.*)$"
)
REPEATED_PATTERN = re.compile(
    r"^message repeated (?P<count>\d+) times:\s*\[\s*(?P<body>.*?)\s*\]$"
)
ACCEPTED_PATTERN = re.compile(
    r"^Accepted (?P<method>password|publickey) for (?P<username>\S+) "
    r"from (?P<ip>\S+)(?:\s|$)"
)
FAILED_PATTERN = re.compile(
    r"^Failed (?P<method>password|publickey) for "
    r"(?:(?P<invalid>invalid user)\s+)?(?P<username>\S+) "
    r"from (?P<ip>\S+)(?:\s|$)"
)


@dataclass(frozen=True)
class SourceLine:
    """Ligne lue avec son fichier d'origine."""

    path: Path
    number: int
    text: str


@dataclass(frozen=True)
class LogEvent:
    """Événement SSH utile aux agrégations."""

    timestamp: datetime
    source_file: str
    line_number: int
    ip_address: str
    username: str
    status: str
    occurrences: int = 1
    country: str = "Inconnu"


@dataclass(frozen=True)
class PipelineStats:
    """Résumé de la dernière exécution."""

    files: int
    lines: int
    events: int
    successful_attempts: int
    failed_attempts: int
    invalid_user_attempts: int


class LogPipeline:
    """Construit et stocke les événements depuis les fichiers auth.log."""

    def __init__(
        self,
        data_directory: Path,
        event_store: Any,
        year: int | None = None,
        request_timeout: float = 3.0,
        geolocate: bool = True,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        self.data_directory = Path(data_directory)
        self.event_store = event_store
        self.year = year or datetime.now().year
        self.request_timeout = request_timeout
        self.geolocate = geolocate
        self.progress_callback = progress_callback
        self._geo_rate_limited = False
        self._country_cache: dict[str, str] = {}

    def _list_files(self) -> list[Path]:
        """Retourne les fichiers du dossier data dans un ordre stable."""
        try:
            files = sorted(
                (entry for entry in self.data_directory.iterdir() if entry.is_file()),
                key=lambda path: path.name.casefold(),
            )
        except FileNotFoundError:
            _INGESTION_LOGGER.exception(
                "Dossier de données introuvable : %s", self.data_directory
            )
            raise
        except PermissionError:
            _INGESTION_LOGGER.exception(
                "Permission refusée pour le dossier %s", self.data_directory
            )
            raise
        except OSError:
            _INGESTION_LOGGER.exception(
                "Lecture impossible du dossier %s", self.data_directory
            )
            raise

        if not files:
            message = f"Aucun fichier de log trouvé dans {self.data_directory}"
            _INGESTION_LOGGER.error(message)
            raise FileNotFoundError(message)
        _INGESTION_LOGGER.info(
            "%d fichiers de données trouvés dans %s", len(files), self.data_directory
        )
        return files

    def _read_files(self) -> tuple[list[SourceLine], int]:
        """Lit chaque fichier séparément pour isoler les erreurs de lecture."""
        source_lines: list[SourceLine] = []
        files = self._list_files()

        for path in files:
            opener = gzip.open if path.suffix.casefold() == ".gz" else open
            try:
                with opener(path, "rt", encoding="utf-8", errors="strict") as stream:
                    for number, line in enumerate(stream, start=1):
                        source_lines.append(SourceLine(path, number, line))
            except gzip.BadGzipFile:
                _INGESTION_LOGGER.exception("Archive gzip corrompue : %s", path)
            except EOFError:
                _INGESTION_LOGGER.exception("Archive gzip tronquée : %s", path)
            except UnicodeDecodeError:
                _INGESTION_LOGGER.exception("Encodage invalide dans %s", path)
            except PermissionError:
                _INGESTION_LOGGER.exception("Permission refusée pour le fichier %s", path)
            except FileNotFoundError:
                _INGESTION_LOGGER.exception("Fichier disparu pendant la lecture : %s", path)
            except OSError:
                _INGESTION_LOGGER.exception("Erreur de lecture pour %s", path)

        _INGESTION_LOGGER.info(
            "%d lignes lues dans %d fichiers", len(source_lines), len(files)
        )
        return source_lines, len(files)

    @staticmethod
    def _parse_line(source: SourceLine, year: int) -> tuple[LogEvent | None, int]:
        """Analyse une ligne et renvoie aussi son nombre d'échecs password."""
        record = SYSLOG_PATTERN.match(source.text.rstrip("\r\n"))
        if record is None:
            if "sshd[" in source.text and any(
                marker in source.text
                for marker in ("Failed password", "Accepted password", "Accepted publickey")
            ):
                _PROCESSING_LOGGER.warning(
                    "Ligne SSH non parsable (%s:%d) : %s",
                    source.path.name,
                    source.number,
                    source.text.strip(),
                )
            return None, 0

        body = record.group("body").strip()
        occurrences = 1
        repeated = REPEATED_PATTERN.fullmatch(body)
        if repeated is not None:
            try:
                occurrences = int(repeated.group("count"))
            except ValueError:
                _PROCESSING_LOGGER.exception(
                    "Nombre de répétitions invalide (%s:%d)",
                    source.path.name,
                    source.number,
                )
                return None, 0
            if occurrences < 1:
                _PROCESSING_LOGGER.warning(
                    "Nombre de répétitions nul ou négatif (%s:%d)",
                    source.path.name,
                    source.number,
                )
                return None, 0
            body = repeated.group("body").strip()

        accepted = ACCEPTED_PATTERN.match(body)
        failed = FAILED_PATTERN.match(body)
        password_failures = 0

        if accepted is not None:
            username = accepted.group("username")
            ip_address = accepted.group("ip")
            status = "Success"
        elif failed is not None:
            username = failed.group("username")
            ip_address = failed.group("ip")
            status = "Invalid" if failed.group("invalid") else "Failed"
            if failed.group("method") == "password":
                password_failures = occurrences
        else:
            # Ces lignes décrivent la connexion, sans compter un échec de mot de passe.
            if body.startswith(
                (
                    "Invalid user ",
                    "Connection closed by invalid user ",
                    "Disconnected from invalid user ",
                )
            ):
                return None, 0
            if body.startswith(
                ("Failed password", "Failed publickey", "Accepted password", "Accepted publickey")
            ):
                _PROCESSING_LOGGER.warning(
                    "Message SSH d'authentification non parsable (%s:%d) : %s",
                    source.path.name,
                    source.number,
                    body,
                )
            return None, 0

        try:
            timestamp = datetime(
                year,
                MONTHS[record.group("month")],
                int(record.group("day")),
                int(record.group("hour")),
                int(record.group("minute")),
                int(record.group("second")),
            )
        except (KeyError, ValueError):
            _PROCESSING_LOGGER.exception(
                "Date syslog invalide (%s:%d) : %s",
                source.path.name,
                source.number,
                source.text.strip(),
            )
            return None, 0

        try:
            ipaddress.ip_address(ip_address.strip("[]"))
        except ValueError:
            _PROCESSING_LOGGER.error(
                "Adresse IP invalide (%s:%d) : %s",
                source.path.name,
                source.number,
                ip_address,
            )

        event = LogEvent(
            timestamp=timestamp,
            source_file=source.path.name,
            line_number=source.number,
            ip_address=ip_address.strip("[]"),
            username=username,
            status=status,
            occurrences=occurrences,
        )
        return event, password_failures

    def _lookup_country(self, ip_text: str) -> str:
        """Résout une IP publique une seule fois avec un délai maximal."""
        if ip_text in self._country_cache:
            return self._country_cache[ip_text]

        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            _PROCESSING_LOGGER.error(
                "Géolocalisation ignorée pour l'IP invalide %s", ip_text
            )
            self._country_cache[ip_text] = "Inconnu"
            return "Inconnu"

        if self._geo_rate_limited and address.is_global:
            self._country_cache[ip_text] = "Inconnu"
            return "Inconnu"

        if address.is_loopback:
            country = "Locale"
        elif address.is_private:
            country = "Privée"
        elif not address.is_global:
            country = "Non publique"
        elif not self.geolocate:
            country = "Inconnu"
        else:
            token = os.environ.get("IPINFO_TOKEN")
            if token:
                url = f"https://api.ipinfo.io/lite/{quote(ip_text, safe='')}"
                headers = {"Authorization": f"Bearer {token}"}
            else:
                url = f"https://ipinfo.io/{quote(ip_text, safe='')}/json"
                headers = None
            try:
                with requests.get(
                    url, timeout=self.request_timeout, headers=headers
                ) as response:
                    if response.status_code == 429:
                        self._geo_rate_limited = True
                        _PROCESSING_LOGGER.error(
                            "ipinfo a limité les requêtes (HTTP 429); géolocalisation interrompue pour les autres IP publiques"
                        )
                        self._country_cache[ip_text] = "Inconnu"
                        return "Inconnu"
                    if response.status_code != 200:
                        _PROCESSING_LOGGER.error(
                            "ipinfo a répondu HTTP %d pour %s",
                            response.status_code,
                            ip_text,
                        )
                        self._country_cache[ip_text] = "Inconnu"
                        return "Inconnu"
                    payload = response.json()
                if not isinstance(payload, dict):
                    _PROCESSING_LOGGER.error(
                        "Réponse JSON ipinfo invalide pour %s", ip_text
                    )
                    country = "Inconnu"
                else:
                    country = str(payload.get("country_code") or payload.get("country") or "").strip().upper()
                    if not country:
                        _PROCESSING_LOGGER.warning(
                            "Pays absent de la réponse ipinfo pour %s", ip_text
                        )
                        country = "Inconnu"
            except requests.Timeout:
                _PROCESSING_LOGGER.exception(
                    "Délai dépassé pendant la géolocalisation de %s", ip_text
                )
                country = "Inconnu"
            except requests.HTTPError:
                _PROCESSING_LOGGER.exception(
                    "Erreur HTTP pendant la géolocalisation de %s", ip_text
                )
                country = "Inconnu"
            except requests.RequestException:
                _PROCESSING_LOGGER.exception(
                    "Erreur réseau pendant la géolocalisation de %s", ip_text
                )
                country = "Inconnu"
            except ValueError:
                _PROCESSING_LOGGER.exception(
                    "Réponse JSON ipinfo illisible pour %s", ip_text
                )
                country = "Inconnu"

        self._country_cache[ip_text] = country
        return country

    def run(self) -> PipelineStats:
        """Lit, analyse, enrichit puis enregistre les événements."""
        source_lines, file_count = self._read_files()
        events: list[LogEvent] = []
        password_failure_count = 0

        for source in source_lines:
            try:
                event, password_failures = self._parse_line(source, self.year)
            except (KeyError, TypeError, ValueError):
                _PROCESSING_LOGGER.exception(
                    "Erreur de parsing (%s:%d)", source.path.name, source.number
                )
                continue
            if event is not None:
                events.append(event)
                password_failure_count += password_failures

        # Le parseur historique sert de point de comparaison.
        try:
            historical = extract_transforme.extract_from_rows(
                [source.text for source in source_lines]
            )
            historical_count = sum(item["nb"] for item in historical)
            if historical_count != password_failure_count:
                _PROCESSING_LOGGER.warning(
                    "Écart avec extract_transforme : adapter=%d, module existant=%d",
                    password_failure_count,
                    historical_count,
                )
        except (KeyError, TypeError, ValueError):
            _PROCESSING_LOGGER.exception(
                "Comparaison avec extract_transforme impossible"
            )

        unique_ips = list(dict.fromkeys(event.ip_address for event in events))
        countries: dict[str, str] = {}
        for completed, ip_address in enumerate(unique_ips, start=1):
            countries[ip_address] = self._lookup_country(ip_address)
            if self.progress_callback and (
                completed % 100 == 0 or completed == len(unique_ips)
            ):
                self.progress_callback(completed, len(unique_ips))

        enriched_events = [
            replace(event, country=countries.get(event.ip_address, "Inconnu"))
            for event in events
        ]
        self.event_store.save_events(enriched_events)

        successful = sum(
            event.occurrences for event in enriched_events if event.status == "Success"
        )
        failed = sum(
            event.occurrences for event in enriched_events if event.status == "Failed"
        )
        invalid = sum(
            event.occurrences for event in enriched_events if event.status == "Invalid"
        )
        _LOGGER.info(
            "Analyse terminée : fichiers=%d lignes=%d événements=%d réussies=%d échouées=%d utilisateurs_invalides=%d",
            file_count,
            len(source_lines),
            len(enriched_events),
            successful,
            failed,
            invalid,
        )
        return PipelineStats(
            files=file_count,
            lines=len(source_lines),
            events=len(enriched_events),
            successful_attempts=successful,
            failed_attempts=failed,
            invalid_user_attempts=invalid,
        )




