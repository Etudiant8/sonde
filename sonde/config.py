"""Réglages de la sonde, lus dans un fichier TOML (tout est optionnel)."""
from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


@dataclass
class Config:
    # --- Emplacements ---
    dossier_donnees: str = "/var/lib/sonde"
    journal_eve: str = "/var/log/suricata/eve-*.json"   # un fichier par jour
    dossier_zeek: str = ""                 # vide = Zeek non utilisé
    dossier_journaux: str = "/var/log/suricata"

    # --- Réseau du client ---
    nom_client: str = "Client"
    reseaux_internes: list[str] = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8", "fe80::/10"])
    fuseau: str = "Indian/Reunion"
    heure_ouverture: int = 7               # heures ouvrées : de 7 h à 19 h
    heure_fermeture: int = 19
    jours_ouvres: list[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])  # lundi = 0

    # --- Apprentissage et regroupement ---
    apprentissage_heures: int = 168        # une semaine de réglage
    fenetre_incident_minutes: int = 120
    fenetre_doublon_heures: int = 24

    # --- Seuils de détection ---
    balayage_fenetre_secondes: int = 300
    balayage_machines: int = 10            # machines internes différentes, même port
    balayage_ports: int = 30               # ports différents sur une même machine
    sortie_plancher_mo: int = 500          # volume sortant par jour, en mégaoctets
    sortie_facteur: float = 3.0            # x fois la médiane des jours précédents
    sortie_jours_min: int = 3
    hors_heures_plancher_mo: int = 50
    hors_heures_nuits_habituelles: int = 2
    ports_habituels: list[int] = field(default_factory=lambda: [
        53, 80, 123, 443, 465, 587, 993, 995, 853, 5222, 5223, 5228, 8080, 8443, 3478, 3479, 19302])
    ports_non_chiffres: dict[str, str] = field(default_factory=lambda: {
        "21": "FTP", "23": "Telnet", "69": "TFTP", "110": "POP3", "143": "IMAP"})
    passerelle_max_adresses: int = 8       # au-delà, une MAC est considérée comme un routeur
    fichier_pays: str = ""                 # CSV "debut,fin,pays" (ex. DB-IP Lite) ; vide = désactivé
    fichier_fabricants: str = ""           # fichier "manuf" de Wireshark ; vide = désactivé

    # --- Conservation ---
    conservation_jours: int = 90
    journaux_max_go: float = 20.0

    # --- Surveillance de la sonde ---
    silence_max_minutes: int = 30
    url_signal_de_vie: str = ""            # optionnel, avec accord écrit du client (N11)

    # --- Courriel (F20) ---
    smtp_serveur: str = ""
    smtp_port: int = 587
    smtp_utilisateur: str = ""
    smtp_mot_de_passe: str = ""
    smtp_tls: bool = True
    courriel_expediteur: str = ""
    courriel_destinataires: list[str] = field(default_factory=list)

    # --- Export vers un SOC partenaire (F21) ---
    export_fichier: str = ""               # chemin d'un fichier JSON (une alerte par ligne)
    export_syslog_hote: str = ""
    export_syslog_port: int = 514
    export_syslog_protocole: str = "udp"   # udp ou tcp

    # --- Interface web ---
    web_verrouillage_essais: int = 5
    web_verrouillage_minutes: int = 15
    web_session_minutes: int = 60

    def __post_init__(self) -> None:
        self._reseaux = [ipaddress.ip_network(r, strict=False) for r in self.reseaux_internes]
        for champ in ("heure_ouverture", "heure_fermeture"):
            if not 0 <= getattr(self, champ) <= 24:
                raise ValueError(f"{champ} doit être entre 0 et 24")
        if self.export_syslog_protocole not in ("udp", "tcp"):
            raise ValueError("export_syslog_protocole doit valoir udp ou tcp")

    def est_interne(self, ip: str) -> bool:
        try:
            adresse = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(adresse in r for r in self._reseaux)

    @property
    def chemin_base(self) -> Path:
        return Path(self.dossier_donnees) / "sonde.db"


def charger(chemin: str | Path | None) -> Config:
    """Lit le fichier de réglages. Un réglage inconnu est une erreur (faute de frappe)."""
    if not chemin:
        return Config()
    with open(chemin, "rb") as f:
        brut = tomllib.load(f)
    connus = {c.name for c in fields(Config)}
    inconnus = sorted(set(brut) - connus)
    if inconnus:
        raise ValueError("Réglage(s) inconnu(s) : " + ", ".join(inconnus))
    return Config(**brut)
