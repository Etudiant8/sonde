"""Détecteurs (besoins F4 à F10).

``Detecteurs.traiter`` reçoit les événements un par un, tient l'inventaire à
jour et signale au journal ce qui est anormal. Pendant la période
d'apprentissage, la sonde observe les habitudes du réseau : seuls les signaux
qui ne dépendent pas des habitudes (attaque connue, balayage, points faibles)
sont remontés.
"""
from __future__ import annotations

import ipaddress
import logging
import statistics
from datetime import datetime
from typing import Callable
from zoneinfo import ZoneInfo

from .alertes import ELEVEE, FAIBLE, MOYENNE, Journal
from .config import Config
from .inventaire import Inventaire
from .lecture import Evenement
from .stockage import Base

journal_technique = logging.getLogger("sonde.detection")
MO = 1_000_000


class Detecteurs:
    def __init__(self, base: Base, config: Config, inventaire: Inventaire, journal: Journal,
                 pays_de: Callable[[str], str | None] | None = None) -> None:
        self.base = base
        self.config = config
        self.inventaire = inventaire
        self.journal = journal
        self.pays_de = pays_de
        self._fuseau = ZoneInfo(config.fuseau)
        self._installe_le: float | None = None

    # ---------------------------------------------------------------- entrée
    def traiter(self, e: Evenement) -> None:
        try:
            self._noter_installation(e.quand)
            if e.type == "flux":
                self._flux(e)
            elif e.type == "alerte":
                self._signature(e)
            elif e.type == "dns":
                for _question, ip in e.donnees.get("reponses", []):
                    self._retenir_nom(ip, e.donnees.get("question", ""), e.quand)
            elif e.type == "nom":
                self._retenir_nom(e.ip_dst, e.donnees.get("nom", ""), e.quand)
            elif e.type == "dhcp":
                self._dhcp(e)
        except Exception:  # un événement abîmé ne doit jamais arrêter la surveillance
            journal_technique.exception("Événement ignoré : %r", e)

    def entretien(self, maintenant: float) -> None:
        self.base.executer("DELETE FROM flux_recents WHERE quand < ?",
                           (maintenant - 2 * self.config.balayage_fenetre_secondes,))

    # --------------------------------------------------------- apprentissage
    def _noter_installation(self, quand: float) -> None:
        if self._installe_le is None:
            connu = self.base.lire_meta("installe_le")
            if connu is None:
                self.base.ecrire_meta("installe_le", repr(quand))
                connu = repr(quand)
            self._installe_le = float(connu)

    def en_apprentissage(self, quand: float) -> bool:
        if self._installe_le is None:
            connu = self.base.lire_meta("installe_le")
            if connu is None:
                return True
            self._installe_le = float(connu)
        return quand < self._installe_le + self.config.apprentissage_heures * 3600

    # ------------------------------------------------------------ inventaire
    def _voir(self, ip: str, quand: float, mac: str | None = None, nom: str | None = None) -> int:
        ident, nouveau = self.inventaire.voir(ip, quand, mac, nom)
        if nouveau and not self.en_apprentissage(quand):
            self.journal.signaler("nouvel_appareil", ident, "", MOYENNE, quand, {})
        return ident

    def _dhcp(self, e: Evenement) -> None:
        ip, mac = e.donnees.get("ip", ""), e.donnees.get("mac", "")
        if ip and mac and self.config.est_interne(ip):
            self._voir(ip, e.quand, mac, e.donnees.get("nom") or None)

    def _retenir_nom(self, ip: str, nom: str, quand: float) -> None:
        if ip and nom:
            self.base.executer(
                "INSERT INTO noms_dns(ip, nom, vu) VALUES(?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET nom=excluded.nom, vu=excluded.vu", (ip, nom[:200], quand))

    def _nom_de(self, ip: str) -> str | None:
        ligne = self.base.un("SELECT nom FROM noms_dns WHERE ip=?", (ip,))
        return ligne["nom"] if ligne else None

    # ------------------------------------------------------------- signature
    def _signature(self, e: Evenement) -> None:
        # Les règles internes de Suricata (n° 2200000 à 2299999) signalent des anomalies de
        # décodage du trafic, pas des attaques : elles noieraient le client sous le bruit.
        if 2_200_000 <= int(e.donnees.get("sid", 0) or 0) < 2_300_000:
            return
        src_interne, dst_interne = self.config.est_interne(e.ip_src), self.config.est_interne(e.ip_dst)
        if src_interne:
            interne, tiers = e.ip_src, e.ip_dst
        elif dst_interne:
            interne, tiers = e.ip_dst, e.ip_src
        else:
            interne, tiers = None, e.ip_src
        appareil = self._voir(interne, e.quand) if interne else None
        gravite = {1: ELEVEE, 2: MOYENNE}.get(e.donnees.get("gravite_suricata", 3), FAIBLE)
        self.journal.signaler("signature", appareil, str(e.donnees.get("sid", "")), gravite, e.quand, {
            "signature": e.donnees.get("signature", ""), "categorie": e.donnees.get("categorie", ""),
            "tiers": tiers, "port": e.port_dst,
        })

    # ------------------------------------------------------------------ flux
    def _flux(self, e: Evenement) -> None:
        src_interne = self.config.est_interne(e.ip_src) and _est_machine(e.ip_src)
        dst_interne = self.config.est_interne(e.ip_dst) and _est_machine(e.ip_dst)
        if not src_interne and not dst_interne:
            return
        source = self._voir(e.ip_src, e.quand, e.mac_src) if src_interne else None
        # une cible n'existe que si elle a répondu (sinon un balayage remplirait l'inventaire)
        cible = self._voir(e.ip_dst, e.quand, e.mac_dst) if dst_interne and e.etabli else None

        if src_interne and dst_interne:
            if e.etabli:
                self._non_chiffre(e, cible, FAIBLE)
            else:
                self._balayage(e, source)
        elif src_interne:
            if e.etabli:
                self._non_chiffre(e, source, MOYENNE)
                self._destination(e, source)
                self._volume_sortant(e, source)
                self._hors_heures(e, source)
        elif e.etabli:
            self.journal.signaler("service_expose", cible, str(e.port_dst), MOYENNE, e.quand,
                                  {"port": e.port_dst, "service": e.app, "depuis": e.ip_src}, categorie="faiblesse")

    # F10 ------------------------------------------------------------------
    def _non_chiffre(self, e: Evenement, appareil: int, gravite: int) -> None:
        protocole = self.config.ports_non_chiffres.get(str(e.port_dst))
        if protocole:
            self.journal.signaler("non_chiffre", appareil, str(e.port_dst), gravite, e.quand,
                                  {"port": e.port_dst, "protocole": protocole}, categorie="faiblesse")

    # F7 -------------------------------------------------------------------
    def _balayage(self, e: Evenement, source: int) -> None:
        self.base.executer("INSERT INTO flux_recents(quand, ip_src, ip_dst, port_dst, etabli) VALUES(?, ?, ?, ?, 0)",
                           (e.quand, e.ip_src, e.ip_dst, e.port_dst))
        # Les flux n'arrivent pas dans l'ordre : on relit ceux qui entourent l'événement
        # et on cherche la fenêtre glissante la plus chargée.
        largeur = self.config.balayage_fenetre_secondes
        autour = (e.quand - largeur, e.quand + largeur)
        machines = _max_distincts(self.base.tous(
            "SELECT quand, ip_dst v FROM flux_recents WHERE ip_src=? AND port_dst=? AND quand BETWEEN ? AND ? ORDER BY quand",
            (e.ip_src, e.port_dst, *autour)), largeur)
        if machines >= self.config.balayage_machines:
            self.journal.signaler("balayage", source, f"port:{e.port_dst}", MOYENNE, e.quand,
                                  {"port": e.port_dst, "machines": machines})
        ports = _max_distincts(self.base.tous(
            "SELECT quand, port_dst v FROM flux_recents WHERE ip_src=? AND ip_dst=? AND quand BETWEEN ? AND ? ORDER BY quand",
            (e.ip_src, e.ip_dst, *autour)), largeur)
        if ports >= self.config.balayage_ports:
            self.journal.signaler("balayage", source, f"cible:{e.ip_dst}", MOYENNE, e.quand,
                                  {"cible": e.ip_dst, "ports": ports})

    # F8 -------------------------------------------------------------------
    def _destination(self, e: Evenement, source: int) -> None:
        apprentissage = self.en_apprentissage(e.quand)
        deja_vue = self.base.un("SELECT 1 FROM destinations WHERE ip=? LIMIT 1", (e.ip_dst,)) is not None
        self.base.executer(
            "INSERT INTO destinations(appareil_id, ip, premiere_vue, derniere_vue) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(appareil_id, ip) DO UPDATE SET derniere_vue=MAX(derniere_vue, excluded.derniere_vue)",
            (source, e.ip_dst, e.quand, e.quand))
        if (not deja_vue and not apprentissage and e.port_dst not in self.config.ports_habituels
                and self._nom_de(e.ip_dst) is None):
            self.journal.signaler("destination_inhabituelle", source, f"{e.ip_dst}:{e.port_dst}", FAIBLE, e.quand,
                                  {"ip": e.ip_dst, "port": e.port_dst})
        if self.pays_de:
            pays = self.pays_de(e.ip_dst)
            if pays and not self.base.un("SELECT 1 FROM pays_vus WHERE pays=?", (pays,)):
                self.base.executer("INSERT INTO pays_vus(pays, premiere_vue) VALUES(?, ?)", (pays, e.quand))
                if not apprentissage:
                    self.journal.signaler("nouveau_pays", source, pays, FAIBLE, e.quand, {"pays": pays, "ip": e.ip_dst})

    # F6 -------------------------------------------------------------------
    def _volume_sortant(self, e: Evenement, source: int) -> None:
        if e.octets_envoyes <= 0:
            return
        jour = self._local(e.quand).strftime("%Y-%m-%d")
        self.base.executer(
            "INSERT INTO sortie_jour(appareil_id, jour, octets) VALUES(?, ?, ?) "
            "ON CONFLICT(appareil_id, jour) DO UPDATE SET octets=octets+excluded.octets", (source, jour, e.octets_envoyes))
        if self.en_apprentissage(e.quand):
            return
        total = self.base.un("SELECT octets FROM sortie_jour WHERE appareil_id=? AND jour=?", (source, jour))["octets"]
        plancher = self.config.sortie_plancher_mo * MO
        if total <= plancher:
            return
        passe = [l["octets"] for l in self.base.tous(
            "SELECT octets FROM sortie_jour WHERE appareil_id=? AND jour<? ORDER BY jour DESC LIMIT 30", (source, jour))]
        habituel = int(statistics.median(passe)) if len(passe) >= self.config.sortie_jours_min else None
        seuil = max(plancher, self.config.sortie_facteur * habituel) if habituel else plancher
        if total > seuil:
            detail = {"octets": total, "destination": self._nom_de(e.ip_dst) or e.ip_dst}
            if habituel:
                detail["habituel"] = habituel
            self.journal.signaler("sortie_volume", source, "", MOYENNE, e.quand, detail)

    # F9 -------------------------------------------------------------------
    def _hors_heures(self, e: Evenement, source: int) -> None:
        local = self._local(e.quand)
        ouvre = (local.weekday() in self.config.jours_ouvres
                 and self.config.heure_ouverture <= local.hour < self.config.heure_fermeture)
        if ouvre or e.octets_envoyes <= 0:
            return
        jour = local.strftime("%Y-%m-%d")
        self.base.executer(
            "INSERT INTO hors_heures(appareil_id, jour, octets) VALUES(?, ?, ?) "
            "ON CONFLICT(appareil_id, jour) DO UPDATE SET octets=octets+excluded.octets", (source, jour, e.octets_envoyes))
        if self.en_apprentissage(e.quand):
            return
        plancher = self.config.hors_heures_plancher_mo * MO
        total = self.base.un("SELECT octets FROM hors_heures WHERE appareil_id=? AND jour=?", (source, jour))["octets"]
        if total <= plancher:
            return
        nuits = self.base.un("SELECT COUNT(*) n FROM hors_heures WHERE appareil_id=? AND jour<? AND octets>?",
                             (source, jour, plancher))["n"]
        if nuits < self.config.hors_heures_nuits_habituelles:
            self.journal.signaler("hors_heures", source, "", FAIBLE, e.quand, {"octets": total})

    def _local(self, quand: float) -> datetime:
        return datetime.fromtimestamp(quand, self._fuseau)


def _est_machine(ip: str) -> bool:
    """Écarte les adresses qui ne désignent pas une machine (diffusion, multidiffusion, 0.0.0.0)."""
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (adresse.is_multicast or adresse.is_unspecified or ip == "255.255.255.255")


def _max_distincts(lignes, largeur: float) -> int:
    """Plus grand nombre de valeurs différentes dans une fenêtre glissante de ``largeur`` secondes.

    ``lignes`` est trié par date ; chaque ligne porte ``quand`` et ``v``.
    """
    presents: dict = {}
    meilleur = debut = 0
    for ligne in lignes:
        presents[ligne["v"]] = presents.get(ligne["v"], 0) + 1
        while ligne["quand"] - lignes[debut]["quand"] > largeur:
            ancienne = lignes[debut]["v"]
            presents[ancienne] -= 1
            if not presents[ancienne]:
                del presents[ancienne]
            debut += 1
        meilleur = max(meilleur, len(presents))
    return meilleur
