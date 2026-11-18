"""Courriel d'alerte pour les incidents de gravité élevée (besoin F20)."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Callable

from .alertes import ELEVEE
from .config import Config

journal_technique = logging.getLogger("sonde.notification")


def envoyer_smtp(config: Config, message: EmailMessage) -> None:
    with smtplib.SMTP(config.smtp_serveur, config.smtp_port, timeout=20) as serveur:
        if config.smtp_tls:
            serveur.starttls(context=ssl.create_default_context())
        if config.smtp_utilisateur:
            serveur.login(config.smtp_utilisateur, config.smtp_mot_de_passe)
        serveur.send_message(message)


def _une_ligne(texte: str) -> str:
    """Empêche l'injection d'en-têtes : aucun retour à la ligne dans un objet de courriel."""
    return " ".join(str(texte).split())


class Notificateur:
    """À brancher sur ``Sonde.apres_cycle`` : envoie un courriel par incident élevé."""

    def __init__(self, config: Config, envoyer: Callable[[EmailMessage], None] | None = None) -> None:
        self.config = config
        self._envoyer = envoyer or (lambda message: envoyer_smtp(config, message))

    def __call__(self, sonde, maintenant: float) -> None:
        c = self.config
        if not (c.smtp_serveur and c.courriel_expediteur and c.courriel_destinataires):
            return
        a_envoyer = sonde.base.tous(
            "SELECT id FROM incidents WHERE etat='ouvert' AND gravite=? AND gravite_notifiee<?", (ELEVEE, ELEVEE))
        for ligne in a_envoyer:
            incident = sonde.journal.incident(ligne["id"])
            try:
                self._envoyer(self._message(incident))
            except Exception as erreur:      # on réessaiera au prochain cycle
                journal_technique.warning("Courriel non envoyé pour l'incident %s : %s", incident["id"], erreur)
                continue
            sonde.base.executer("UPDATE incidents SET gravite_notifiee=? WHERE id=?", (ELEVEE, incident["id"]))

    def _message(self, incident: dict) -> EmailMessage:
        m = EmailMessage()
        m["From"] = self.config.courriel_expediteur
        m["To"] = ", ".join(self.config.courriel_destinataires)
        m["Subject"] = _une_ligne(
            f"[Sonde] {self.config.nom_client} : incident de gravité élevée sur {incident['appareil_nom']}")
        m.set_content(
            f"Bonjour,\n\nLa sonde de {self.config.nom_client} a relevé un incident de gravité élevée.\n\n"
            f"Ce qui s'est passé :\n{incident['resume']}\n\n"
            f"Ce que nous vous conseillons :\n{incident['action']}\n\n"
            f"Le détail est disponible dans l'interface de la sonde (incident n° {incident['id']}).\n\n"
            "Ce message est envoyé automatiquement par la sonde installée dans vos locaux.\n")
        return m
