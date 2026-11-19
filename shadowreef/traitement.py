"""Chaîne complète de la sonde : lire les journaux, détecter, surveiller, nettoyer.

``Sonde.cycle`` est appelé toutes les 30 secondes par la commande ``shadowreef
surveiller``. Il reprend la lecture là où il s'était arrêté, même après une
coupure de courant (N8), car la position de lecture est enregistrée dans la
même transaction que les événements traités.
"""
from __future__ import annotations

import glob
import logging
import os
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo

from . import __version__
from .alertes import ELEVEE, Journal
from .config import Config
from .detection import Detecteurs
from .inventaire import Inventaire
from .lecture import Evenement, lire_ligne_eve, lire_ligne_zeek
from .pays import charger_pays
from .stockage import Base

journal_technique = logging.getLogger("shadowreef")
TRANCHE = 4 * 1024 * 1024          # octets lus par tranche
PERIODE_SIGNAL_DE_VIE = 300        # secondes
JOURNAUX_ZEEK = ("dhcp", "dns", "conn")


def _ouvrir_url(url: str, delai: float) -> None:
    with urllib.request.urlopen(url, timeout=delai):   # noqa: S310 - adresse choisie par l'installateur
        pass


class Sonde:
    def __init__(self, config: Config, ouvrir_url: Callable[[str, float], None] = _ouvrir_url) -> None:
        self.config = config
        self.base = Base(config.chemin_base)
        self.base.initialiser()
        self.inventaire = Inventaire(self.base, config)
        self.journal = Journal(self.base, config, self.inventaire)
        self.detecteurs = Detecteurs(self.base, config, self.inventaire, self.journal,
                                     pays_de=charger_pays(config.fichier_pays))
        self.apres_cycle: list[Callable[["Sonde", float], None]] = []
        self._ouvrir_url = ouvrir_url
        self._dernier_signal = 0.0

    def fermer(self) -> None:
        self.base.fermer()

    # ----------------------------------------------------------------- cycle
    def cycle(self, maintenant: float | None = None) -> dict:
        maintenant = time.time() if maintenant is None else maintenant
        if self.base.lire_meta("demarre_le") is None:
            self.base.ecrire_meta("demarre_le", repr(maintenant))
        bilan = {"evenements": 0, "lignes_ignorees": 0}
        for chemin in sorted(glob.glob(self.config.journal_eve)):
            self._suivre(chemin, lire_ligne_eve, bilan)
        if self.config.dossier_zeek:
            for nom in JOURNAUX_ZEEK:
                chemin = os.path.join(self.config.dossier_zeek, f"{nom}.log")
                if os.path.isfile(chemin):
                    self._suivre(chemin, lambda ligne, nom=nom: lire_ligne_zeek(ligne, nom), bilan)
        if bilan["evenements"]:
            self.base.ecrire_meta("dernier_trafic", repr(maintenant))
        self._surveiller(maintenant, bilan["evenements"] > 0)
        self.detecteurs.entretien(maintenant)
        self._purger(maintenant)
        self._signal_de_vie(maintenant)
        for action in self.apres_cycle:
            try:
                action(self, maintenant)
            except Exception:
                journal_technique.exception("Une action de fin de cycle a échoué")
        return bilan

    # ------------------------------------------------------ suivi de fichier
    def _suivre(self, chemin: str, lire: Callable[[str], Evenement | None], bilan: dict) -> None:
        cle = f"position:{chemin}"
        try:
            taille = os.path.getsize(chemin)
        except OSError:
            return
        position = int(self.base.lire_meta(cle, "0"))
        if taille < position:          # fichier remis à zéro ou remplacé
            position = 0
        while position < taille:
            with open(chemin, "rb") as f:
                f.seek(position)
                bloc = f.read(TRANCHE)
            fin = bloc.rfind(b"\n")
            if fin < 0:
                if len(bloc) < TRANCHE:
                    return             # dernière ligne encore en cours d'écriture
                fin = len(bloc) - 1    # ligne démesurée : on l'écarte
            utile = bloc[:fin + 1]
            with self.base.lot():
                for brute in utile.split(b"\n"):
                    ligne = brute.decode("utf-8", errors="replace").strip()
                    if not ligne:
                        continue
                    evenement = lire(ligne)
                    if evenement is not None:
                        self.detecteurs.traiter(evenement)
                        bilan["evenements"] += 1
                    elif not (ligne.startswith("{") and ligne.endswith("}")) and not ligne.startswith("#"):
                        bilan["lignes_ignorees"] += 1
                position += len(utile)
                self.base.ecrire_meta(cle, str(position))

    # ----------------------------------------------------------- santé (N9)
    def _reference_trafic(self) -> float | None:
        valeur = self.base.lire_meta("dernier_trafic") or self.base.lire_meta("demarre_le")
        return float(valeur) if valeur else None

    def _surveiller(self, maintenant: float, trafic: bool) -> None:
        if trafic:
            for incident in self.base.tous(
                    "SELECT i.id FROM incidents i WHERE i.etat='ouvert' AND i.appareil_id IS NULL AND EXISTS "
                    "(SELECT 1 FROM alertes a WHERE a.incident_id=i.id AND a.type='sonde_muette')"):
                self.journal.resoudre(incident["id"], maintenant)
            return
        reference = self._reference_trafic()
        if reference is not None and maintenant - reference > self.config.silence_max_minutes * 60:
            self.journal.signaler("sonde_muette", None, "", ELEVEE, maintenant,
                                  {"minutes": int((maintenant - reference) // 60)})

    def sante(self, maintenant: float | None = None) -> dict:
        maintenant = time.time() if maintenant is None else maintenant
        reference = self._reference_trafic()
        silence = int(maintenant - reference) if reference is not None else None
        installe = self.base.lire_meta("installe_le")
        fin = float(installe) + self.config.apprentissage_heures * 3600 if installe else None
        return {
            "version": __version__,
            "dernier_trafic_il_y_a": silence,
            "muette": silence is None or silence > self.config.silence_max_minutes * 60,
            "apprentissage": fin is None or maintenant < fin,
            "fin_apprentissage": fin,
            "appareils": self.base.un("SELECT COUNT(*) n FROM appareils")["n"],
            "incidents_ouverts": self.base.un("SELECT COUNT(*) n FROM incidents WHERE etat='ouvert'")["n"],
        }

    def _signal_de_vie(self, maintenant: float) -> None:
        url = self.config.url_signal_de_vie
        if not url or maintenant - self._dernier_signal < PERIODE_SIGNAL_DE_VIE:
            return
        self._dernier_signal = maintenant
        try:
            self._ouvrir_url(url, 10)
        except Exception as erreur:      # la surveillance continue même sans accès à Internet
            journal_technique.warning("Signal de vie non envoyé : %s", erreur)

    # ----------------------------------------------------- conservation (N3)
    def _purger(self, maintenant: float) -> None:
        limite = maintenant - self.config.conservation_jours * 86400
        jour_limite = datetime.fromtimestamp(limite, ZoneInfo(self.config.fuseau)).strftime("%Y-%m-%d")
        with self.base.lot():
            self.base.executer(
                "DELETE FROM alertes WHERE incident_id IN (SELECT id FROM incidents WHERE etat!='ouvert' AND ferme_le<?)",
                (limite,))
            self.base.executer("DELETE FROM incidents WHERE etat!='ouvert' AND ferme_le<?", (limite,))
            self.base.executer("DELETE FROM sortie_jour WHERE jour<?", (jour_limite,))
            self.base.executer("DELETE FROM hors_heures WHERE jour<?", (jour_limite,))
            self.base.executer("DELETE FROM destinations WHERE derniere_vue<?", (limite,))
            self.base.executer("DELETE FROM noms_dns WHERE vu<?", (limite,))
        self._purger_journaux()

    def _purger_journaux(self) -> None:
        """Supprime les plus vieux journaux quand le plafond d'espace disque est dépassé."""
        fichiers = sorted(glob.glob(self.config.journal_eve))
        plafond = self.config.journaux_max_go * 1e9
        tailles = {}
        for chemin in fichiers:
            try:
                tailles[chemin] = os.path.getsize(chemin)
            except OSError:
                tailles[chemin] = 0
        total = sum(tailles.values())
        for chemin in fichiers[:-1]:           # le journal le plus récent n'est jamais supprimé
            if total <= plafond:
                break
            try:
                os.remove(chemin)
                total -= tailles[chemin]
                self.base.executer("DELETE FROM meta WHERE cle=?", (f"position:{chemin}",))
                journal_technique.info("Journal supprimé pour libérer de la place : %s", Path(chemin).name)
            except OSError as erreur:
                journal_technique.warning("Impossible de supprimer %s : %s", chemin, erreur)


def construire(config: Config) -> Sonde:
    """Sonde complète, avec le courriel d'alerte et l'export branchés sur chaque cycle."""
    from .export import Exporteur
    from .notification import Notificateur

    sonde = Sonde(config)
    sonde.apres_cycle.extend([Notificateur(config), Exporteur(config)])
    return sonde
