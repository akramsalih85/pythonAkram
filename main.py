"""Point d'entrée de l'analyse des journaux SSH."""

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Sequence

from logger_config import get_module_logger
from pipeline.orchestrator import LogPipeline
from serving.dashboard import build_dashboard
from storage.event_store import EventStore

PROJECT_ROOT = Path(__file__).resolve().parent
_LOGGER = get_module_logger(__name__)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse les événements SSH des fichiers auth.log."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=PROJECT_ROOT / "data",
        help="Dossier qui contient les fichiers auth.log.",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=PROJECT_ROOT / "output" / "log_events.sqlite3",
        help="Chemin de la base SQLite générée.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "output",
        help="Dossier de sortie des trois graphiques PNG.",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Année à associer aux dates syslog qui n'en contiennent pas.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Nombre de noms affichés dans les graphiques classés.",
    )
    parser.add_argument(
        "--no-geolocation",
        action="store_true",
        help="Désactive les requêtes ipinfo et classe les IP publiques comme Inconnu.",
    )
    parser.add_argument(
        "--no-show",
        action="store_true",
        help="Enregistre les graphiques sans ouvrir de fenêtres.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Exécute le pipeline, enregistre les résultats et crée le tableau de bord."""
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    if arguments.top_n < 1:
        parser.error("--top-n doit être supérieur ou égal à 1")

    try:
        geo_mode = "activée" if not arguments.no_geolocation else "désactivée"
        _LOGGER.info("Démarrage de l'analyse; géolocalisation %s.", geo_mode)
        store = EventStore(arguments.database)
        pipeline = LogPipeline(
            arguments.data_dir,
            store,
            year=arguments.year,
            geolocate=not arguments.no_geolocation,
            progress_callback=lambda done, total: _LOGGER.info(
                "Géolocalisation des IP : %d/%d", done, total
            ),
        )
        stats = pipeline.run()
        charts = build_dashboard(
            store,
            arguments.output_dir,
            top_n=arguments.top_n,
            show=not arguments.no_show,
        )
        _LOGGER.info(
            "Résultat : %d succès, %d échecs, %d tentatives pour des utilisateurs invalides. Graphiques : %s",
            stats.successful_attempts,
            stats.failed_attempts,
            stats.invalid_user_attempts,
            ", ".join(str(path) for path in charts),
        )
        return 0
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        _LOGGER.exception("Échec global de l'analyse")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())





