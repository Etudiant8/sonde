"""Alertes, incidents et exceptions (besoins F13 à F16).

- Une *alerte* est un signal élémentaire produit par un détecteur.
- Un *incident* regroupe les alertes proches dans le temps d'un même appareil.
- Une *faiblesse* est un point faible durable (service exposé, protocole en
  clair) : elle n'ouvre pas d'incident, elle alimente le rapport.
- Une *exception* empêche une alerte jugée normale de revenir.
"""
from __future__ import annotations

import json

from .config import Config
from .explications import TYPES, conseil, expliquer, phrase
from .inventaire import Inventaire
from .stockage import Base

FAIBLE, MOYENNE, ELEVEE = 1, 2, 3
NOMS_GRAVITE = {FAIBLE: "faible", MOYENNE: "moyenne", ELEVEE: "élevée"}


class Journal:
    def __init__(self, base: Base, config: Config, inventaire: Inventaire) -> None:
        self.base = base
        self.config = config
        self.inventaire = inventaire

    # ------------------------------------------------------------- signaler
    def signaler(self, type_alerte: str, appareil_id: int | None, cle: str, gravite: int, quand: float,
                 detail: dict, categorie: str = "incident") -> int | None:
        """Enregistre un signal. Renvoie l'identifiant de l'alerte, ou None si elle est ignorée."""
        if type_alerte not in TYPES:
            raise ValueError(f"Type d'alerte inconnu : {type_alerte}")
        if gravite not in NOMS_GRAVITE:
            raise ValueError(f"Gravité invalide : {gravite}")
        if categorie not in ("incident", "faiblesse"):
            raise ValueError(f"Catégorie invalide : {categorie}")
        with self.base.lot():
            if self._est_exception(type_alerte, appareil_id, cle):
                return None
            if categorie == "faiblesse":
                return self._signaler_faiblesse(type_alerte, appareil_id, cle, gravite, quand, detail)
            existante = self.base.un(
                "SELECT a.id, a.incident_id FROM alertes a JOIN incidents i ON i.id = a.incident_id "
                "WHERE a.type=? AND a.appareil_id IS ? AND a.cle=? AND i.etat='ouvert' AND a.derniere_vue>=? "
                "ORDER BY a.derniere_vue DESC LIMIT 1",
                (type_alerte, appareil_id, cle, quand - self.config.fenetre_doublon_heures * 3600))
            if existante:
                self.base.executer(
                    "UPDATE alertes SET nombre=nombre+1, derniere_vue=MAX(derniere_vue, ?), detail=?, exportee=0 WHERE id=?",
                    (quand, json.dumps(detail, ensure_ascii=False), existante["id"]))
                self._recalculer(existante["incident_id"], quand)
                return existante["id"]
            incident_id = self._incident_pour(appareil_id, quand)
            curseur = self.base.executer(
                "INSERT INTO alertes(type, categorie, appareil_id, cle, gravite, detail, premiere_vue, derniere_vue, incident_id) "
                "VALUES(?, 'incident', ?, ?, ?, ?, ?, ?, ?)",
                (type_alerte, appareil_id, cle, gravite, json.dumps(detail, ensure_ascii=False), quand, quand, incident_id))
            self._recalculer(incident_id, quand)
            return int(curseur.lastrowid)

    def _signaler_faiblesse(self, type_alerte, appareil_id, cle, gravite, quand, detail) -> int | None:
        existante = self.base.un(
            "SELECT id, etat FROM alertes WHERE categorie='faiblesse' AND type=? AND appareil_id IS ? AND cle=?",
            (type_alerte, appareil_id, cle))
        if existante:
            if existante["etat"] != "ouverte":
                return None
            self.base.executer("UPDATE alertes SET nombre=nombre+1, derniere_vue=MAX(derniere_vue, ?) WHERE id=?",
                               (quand, existante["id"]))
            return existante["id"]
        curseur = self.base.executer(
            "INSERT INTO alertes(type, categorie, appareil_id, cle, gravite, detail, premiere_vue, derniere_vue) "
            "VALUES(?, 'faiblesse', ?, ?, ?, ?, ?, ?)",
            (type_alerte, appareil_id, cle, gravite, json.dumps(detail, ensure_ascii=False), quand, quand))
        return int(curseur.lastrowid)

    def _est_exception(self, type_alerte: str, appareil_id: int | None, cle: str) -> bool:
        return self.base.un(
            "SELECT 1 FROM exceptions WHERE type=? AND (appareil_id IS NULL OR appareil_id IS ?) AND (cle='*' OR cle=?)",
            (type_alerte, appareil_id, cle)) is not None

    def _incident_pour(self, appareil_id: int | None, quand: float) -> int:
        fenetre = self.config.fenetre_incident_minutes * 60
        ouvert = self.base.un(
            "SELECT id FROM incidents WHERE etat='ouvert' AND appareil_id IS ? AND maj_le>=? AND ouvert_le<=? "
            "ORDER BY maj_le DESC LIMIT 1", (appareil_id, quand - fenetre, quand + fenetre))
        if ouvert:
            return ouvert["id"]
        curseur = self.base.executer(
            "INSERT INTO incidents(appareil_id, gravite, ouvert_le, maj_le) VALUES(?, ?, ?, ?)",
            (appareil_id, FAIBLE, quand, quand))
        return int(curseur.lastrowid)

    def _recalculer(self, incident_id: int, quand: float) -> None:
        alertes = self.alertes_de(incident_id)
        if not alertes:
            return
        gravite = max(a["gravite"] for a in alertes)
        if len({a["type"] for a in alertes}) >= 2:      # signaux de natures différentes : plus inquiétant
            gravite = min(ELEVEE, gravite + 1)
        incident = self.base.un("SELECT appareil_id FROM incidents WHERE id=?", (incident_id,))
        resume, action = expliquer(alertes, self._nom(incident["appareil_id"]))
        self.base.executer(
            "UPDATE incidents SET gravite=?, resume=?, action=?, maj_le=MAX(maj_le, ?), ouvert_le=MIN(ouvert_le, ?) WHERE id=?",
            (gravite, resume, action, quand, quand, incident_id))

    def _nom(self, appareil_id: int | None) -> str:
        if appareil_id is None:
            return "le réseau"
        appareil = self.inventaire.appareil(appareil_id)
        if not appareil:
            return f"l'appareil {appareil_id}"
        nom = appareil["nom_affiche"]
        adresse = appareil["adresses"][0] if appareil["adresses"] else ""
        return f"{nom} ({adresse})" if adresse and adresse != nom else nom

    # ------------------------------------------------------------ consulter
    def incidents(self, etat: str | None = None, gravite_min: int = FAIBLE) -> list[dict]:
        sql = "SELECT * FROM incidents WHERE gravite>=?"
        params: list = [gravite_min]
        if etat:
            sql += " AND etat=?"
            params.append(etat)
        sql += " ORDER BY (etat='ouvert') DESC, gravite DESC, maj_le DESC, id DESC"
        return [self._incident_en_dict(l) for l in self.base.tous(sql, tuple(params))]

    def incident(self, incident_id: int) -> dict | None:
        ligne = self.base.un("SELECT * FROM incidents WHERE id=?", (incident_id,))
        return self._incident_en_dict(ligne) if ligne else None

    def _incident_en_dict(self, ligne) -> dict:
        d = dict(ligne)
        d["gravite_nom"] = NOMS_GRAVITE[d["gravite"]]
        d["appareil_nom"] = self._nom(d["appareil_id"])
        return d

    def alertes_de(self, incident_id: int) -> list[dict]:
        lignes = self.base.tous("SELECT * FROM alertes WHERE incident_id=? ORDER BY premiere_vue, id", (incident_id,))
        return [self._alerte_en_dict(l) for l in lignes]

    def _alerte_en_dict(self, ligne) -> dict:
        d = dict(ligne)
        d["detail"] = json.loads(d["detail"])
        d["gravite_nom"] = NOMS_GRAVITE[d["gravite"]]
        d["texte"] = phrase(d["type"], self._nom(d["appareil_id"]), d["detail"], d["gravite"]) + "."
        d["conseil"] = conseil(d["type"], d["gravite"])
        return d

    def faiblesses(self) -> list[dict]:
        lignes = self.base.tous(
            "SELECT * FROM alertes WHERE categorie='faiblesse' AND etat='ouverte' ORDER BY gravite DESC, derniere_vue DESC")
        return [self._alerte_en_dict(l) for l in lignes]

    def etat_general(self) -> str:
        ligne = self.base.un("SELECT MAX(gravite) g FROM incidents WHERE etat='ouvert'")
        pire = ligne["g"] or 0
        return {ELEVEE: "rouge", MOYENNE: "orange"}.get(pire, "vert")

    def exceptions(self) -> list[dict]:
        return [dict(l) for l in self.base.tous("SELECT * FROM exceptions ORDER BY creee_le DESC, id DESC")]

    # ------------------------------------------------------------- décider
    def marquer_normal(self, incident_id: int, commentaire: str = "", quand: float | None = None) -> None:
        """« C'est normal » : ferme l'incident et crée une exception par alerte (F16)."""
        incident = self._incident_ouvert(incident_id)
        with self.base.lot():
            for a in self.alertes_de(incident_id):
                self.base.executer(
                    "INSERT OR IGNORE INTO exceptions(type, appareil_id, cle, commentaire, creee_le) VALUES(?, ?, ?, ?, ?)",
                    (a["type"], a["appareil_id"], a["cle"], commentaire[:200], quand or incident["maj_le"]))
            self.base.executer("UPDATE incidents SET etat='normal', ferme_le=? WHERE id=?",
                               (quand or incident["maj_le"], incident_id))

    def resoudre(self, incident_id: int, quand: float | None = None) -> None:
        incident = self._incident_ouvert(incident_id)
        self.base.executer("UPDATE incidents SET etat='resolu', ferme_le=? WHERE id=?",
                           (quand or incident["maj_le"], incident_id))

    def _incident_ouvert(self, incident_id: int) -> dict:
        incident = self.incident(incident_id)
        if not incident:
            raise KeyError(f"Incident {incident_id} inconnu")
        if incident["etat"] != "ouvert":
            raise ValueError("Cet incident est déjà fermé")
        return incident

    def supprimer_exception(self, exception_id: int) -> None:
        self.base.executer("DELETE FROM exceptions WHERE id=?", (exception_id,))

    def accepter_faiblesse(self, alerte_id: int) -> None:
        curseur = self.base.executer(
            "UPDATE alertes SET etat='normale' WHERE id=? AND categorie='faiblesse'", (alerte_id,))
        if curseur.rowcount == 0:
            raise KeyError(f"Point faible {alerte_id} inconnu")

    def appareil_reconnu(self, appareil_id: int, quand: float) -> None:
        """L'appareil vient d'être marqué connu : ferme les incidents qui ne signalaient que son arrivée."""
        for incident in self.base.tous("SELECT id FROM incidents WHERE etat='ouvert' AND appareil_id=?", (appareil_id,)):
            types = {a["type"] for a in self.alertes_de(incident["id"])}
            if types == {"nouvel_appareil"}:
                self.resoudre(incident["id"], quand)
