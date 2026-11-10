"""Agrégations et graphiques du tableau de bord."""

from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from logger_config import get_module_logger
from storage.event_store import EventStore

_LOGGER = get_module_logger(__name__)


def _plot_bars(
    title: str,
    xlabel: str,
    ylabel: str,
    counts: Counter[str],
    output_path: Path,
    top_n: int | None = None,
    rotation: int = 0,
) -> Any:
    """Construit et sauvegarde un graphique à barres."""
    items = counts.most_common(top_n)
    labels = [label for label, _ in items]
    values = [value for _, value in items]
    width = max(9, min(18, len(labels) * 0.7 + 3))
    figure, axis = plt.subplots(figsize=(width, 5.5))

    if labels:
        axis.bar(range(len(labels)), values, color="#3975a8")
        axis.set_xticks(range(len(labels)))
        axis.set_xticklabels(
            labels,
            rotation=rotation,
            ha="right" if rotation else "center",
        )
    else:
        axis.text(
            0.5,
            0.5,
            "Aucune donnée",
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_xticks([])

    axis.set_title(title)
    axis.set_xlabel(xlabel)
    axis.set_ylabel(ylabel)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    try:
        figure.savefig(output_path, dpi=160, bbox_inches="tight")
    except (OSError, RuntimeError, ValueError):
        _LOGGER.exception("Écriture du graphique impossible : %s", output_path)
        plt.close(figure)
        raise
    _LOGGER.info("Graphique enregistré : %s", output_path)
    return figure


def build_dashboard(
    event_store: EventStore,
    output_directory: Path,
    top_n: int = 10,
    show: bool = True,
) -> tuple[Path, Path, Path]:
    """Crée les trois graphiques PNG et les affiche si demandé."""
    if top_n < 1:
        raise ValueError("top_n doit être supérieur ou égal à 1")

    output_directory = Path(output_directory)
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        _LOGGER.exception(
            "Création impossible du dossier de graphiques %s", output_directory
        )
        raise

    try:
        events = event_store.fetch_events()
        failed_by_country: Counter[str] = Counter()
        successful_by_user: Counter[str] = Counter()
        invalid_by_user: Counter[str] = Counter()

        for event in events:
            count = int(event["occurrences"])
            status = event["status"]
            if status in {"Failed", "Invalid"}:
                failed_by_country[event["country"] or "Inconnu"] += count
            if status == "Success":
                successful_by_user[event["username"] or "(inconnu)"] += count
            if status == "Invalid":
                invalid_by_user[event["username"] or "(inconnu)"] += count

        paths = (
            output_directory / "failed_attempts_by_country.png",
            output_directory / "successful_attempts_by_user.png",
            output_directory / "invalid_user_attempts.png",
        )
        figures = [
            _plot_bars(
                "Tentatives échouées par pays",
                "Pays",
                "Nombre de tentatives",
                failed_by_country,
                paths[0],
                rotation=35,
            ),
            _plot_bars(
                "Tentatives réussies par utilisateur",
                "Utilisateur",
                "Nombre de tentatives",
                successful_by_user,
                paths[1],
                top_n=top_n,
                rotation=35,
            ),
            _plot_bars(
                f"Tentatives pour un utilisateur invalide — top {top_n}",
                "Nom d'utilisateur invalide",
                "Nombre de tentatives",
                invalid_by_user,
                paths[2],
                top_n=top_n,
                rotation=35,
            ),
        ]
        _LOGGER.info(
            "Agrégations terminées : événements=%d pays=%d utilisateurs_réussis=%d utilisateurs_invalides=%d",
            len(events),
            len(failed_by_country),
            len(successful_by_user),
            len(invalid_by_user),
        )
        if show:
            plt.show()
        else:
            for figure in figures:
                plt.close(figure)
        return paths
    except (OSError, RuntimeError, ValueError):
        _LOGGER.exception("Construction du tableau de bord impossible")
        raise
