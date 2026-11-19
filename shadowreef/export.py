"""Export des alertes vers le centre de supervision d'un partenaire (besoin F21).

Deux sorties possibles, à activer dans les réglages : un fichier JSON (une
alerte par ligne) et un envoi syslog au format RFC 5424. Rien n'est envoyé tant
que ce n'est pas configuré (N11).
"""
from __future__ import annotations

import json
import logging
import os
import socket
from datetime import datetime, timezone

from . import __version__
from .alertes import ELEVEE, MOYENNE
from .config import Config

journal_technique = logging.getLogger("shadowreef.export")
LOCAL0 = 16
NIVEAU_SYSLOG = {ELEVEE: 2, MOYENNE: 4}      # critique, avertissement ; sinon 5 (notice)


class Exporteur:
    """À brancher sur ``Sonde.apres_cycle``."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def __call__(self, sonde, maintenant: float) -> None:
        c = self.config
        if not (c.export_fichier or c.export_syslog_hote):
            return
        lignes = sonde.base.tous("SELECT * FROM alertes WHERE exportee=0 ORDER BY derniere_vue, id LIMIT 500")
        for ligne in lignes:
            fiche = self._fiche(sonde, ligne)
            try:
                if c.export_fichier:
                    self._vers_fichier(fiche)
                if c.export_syslog_hote:
                    self._vers_syslog(fiche, ligne["gravite"])
            except OSError as erreur:        # on réessaiera au prochain cycle
                journal_technique.warning("Export interrompu : %s", erreur)
                return
            sonde.base.executer("UPDATE alertes SET exportee=1 WHERE id=?", (ligne["id"],))

    def _fiche(self, sonde, ligne) -> dict:
        alerte = sonde.journal._alerte_en_dict(ligne)
        appareil = sonde.inventaire.appareil(alerte["appareil_id"]) if alerte["appareil_id"] is not None else None
        return {
            "horodatage": datetime.fromtimestamp(alerte["derniere_vue"], timezone.utc).isoformat(timespec="seconds"),
            "produit": "shadowreef",
            "version": __version__,
            "client": self.config.nom_client,
            "id": alerte["id"],
            "incident": alerte["incident_id"],
            "type": alerte["type"],
            "categorie": alerte["categorie"],
            "gravite": alerte["gravite_nom"],
            "nombre": alerte["nombre"],
            "appareil": {"nom": appareil["nom_affiche"], "adresses": appareil["adresses"], "mac": appareil["mac"]} if appareil else None,
            "texte": alerte["texte"],
            "detail": alerte["detail"],
        }

    def _vers_fichier(self, fiche: dict) -> None:
        chemin = self.config.export_fichier
        os.makedirs(os.path.dirname(chemin) or ".", exist_ok=True)
        descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descripteur, "a", encoding="utf-8") as f:
            f.write(json.dumps(fiche, ensure_ascii=False) + "\n")

    def _vers_syslog(self, fiche: dict, gravite: int) -> None:
        priorite = LOCAL0 * 8 + NIVEAU_SYSLOG.get(gravite, 5)
        hote = socket.gethostname().split()[0] or "-"
        message = f"<{priorite}>1 {fiche['horodatage']} {hote} shadowreef - - - {json.dumps(fiche, ensure_ascii=False)}"
        cible = (self.config.export_syslog_hote, self.config.export_syslog_port)
        if self.config.export_syslog_protocole == "tcp":
            with socket.create_connection(cible, timeout=10) as cx:
                cx.sendall(message.encode("utf-8") + b"\n")
        else:
            famille = socket.getaddrinfo(*cible, type=socket.SOCK_DGRAM)[0][0]
            with socket.socket(famille, socket.SOCK_DGRAM) as cx:
                cx.sendto(message.encode("utf-8"), cible)
