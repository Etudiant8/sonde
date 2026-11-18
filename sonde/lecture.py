"""Lecture des journaux réseau (besoins F1, F3, F4).

Deux sources sont comprises :
- le journal JSON de Suricata (eve.json), source principale ;
- les journaux JSON de Zeek (conn, dns, dhcp), source optionnelle.

Chaque ligne utile devient un ``Evenement`` au même format, quelle que soit
la source. Les lignes inutiles ou abîmées sont ignorées (``None``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Evenement:
    quand: float                 # secondes depuis 1970 (UTC)
    type: str                    # flux | dns | dhcp | alerte | nom
    ip_src: str = ""
    ip_dst: str = ""
    port_src: int = 0
    port_dst: int = 0
    proto: str = ""
    mac_src: str | None = None
    mac_dst: str | None = None
    octets_envoyes: int = 0
    octets_recus: int = 0
    etabli: bool = False
    app: str = ""
    donnees: dict[str, Any] = field(default_factory=dict)


def _date(texte: str) -> float:
    # Suricata écrit "2026-05-28T20:26:40.010000+0000"
    return datetime.strptime(texte, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def _mac_unique(valeur: Any) -> str | None:
    """Une MAC n'est fiable que si elle est seule pour ce côté de la connexion."""
    if isinstance(valeur, list) and len(valeur) == 1 and isinstance(valeur[0], str):
        return valeur[0].lower()
    return None


def lire_ligne_eve(ligne: str) -> Evenement | None:
    ligne = ligne.strip()
    if not ligne:
        return None
    try:
        brut = json.loads(ligne)
    except ValueError:
        return None
    if not isinstance(brut, dict):
        return None
    try:
        return _depuis_eve(brut)
    except (KeyError, TypeError, ValueError):
        return None


def _depuis_eve(b: dict) -> Evenement | None:
    genre = b.get("event_type")
    commun = dict(
        ip_src=b.get("src_ip", ""), ip_dst=b.get("dest_ip", ""),
        port_src=int(b.get("src_port", 0) or 0), port_dst=int(b.get("dest_port", 0) or 0),
        proto=str(b.get("proto", "")).upper(), app=str(b.get("app_proto", "") or ""),
    )
    if genre == "flow":
        f = b["flow"]
        vers_client = int(f.get("pkts_toclient", 0) or 0)
        if commun["proto"] == "TCP":
            # le serveur a accepté s'il a répondu avec le drapeau SYN (bit 0x02)
            drapeaux = int(str(b.get("tcp", {}).get("tcp_flags_tc", "0")), 16)
            etabli = bool(drapeaux & 0x02)
        else:
            etabli = vers_client > 0
        ether = b.get("ether", {})
        return Evenement(
            quand=_date(f["start"]), type="flux", etabli=etabli,
            octets_envoyes=int(f.get("bytes_toserver", 0) or 0),
            octets_recus=int(f.get("bytes_toclient", 0) or 0),
            mac_src=_mac_unique(ether.get("src_macs")), mac_dst=_mac_unique(ether.get("dest_macs")),
            **commun,
        )
    if genre == "alert":
        a = b["alert"]
        return Evenement(quand=_date(b["timestamp"]), type="alerte", donnees={
            "signature": str(a.get("signature", "")), "sid": int(a.get("signature_id", 0)),
            "categorie": str(a.get("category", "")), "gravite_suricata": int(a.get("severity", 3)),
        }, **commun)
    if genre == "dns":
        d = b["dns"]
        reponses = []
        if d.get("type") == "answer":
            question = str(d.get("rrname", ""))
            for r in d.get("answers", []) or []:
                if r.get("rrtype") in ("A", "AAAA") and r.get("rdata"):
                    reponses.append((question, str(r["rdata"])))
        return Evenement(quand=_date(b["timestamp"]), type="dns",
                         donnees={"question": str(d.get("rrname", "")), "reponses": reponses}, **commun)
    if genre == "dhcp":
        d = b["dhcp"]
        ip = d.get("assigned_ip")
        if not ip or ip == "0.0.0.0":
            ip = d.get("requested_ip") or d.get("client_ip")
        if not ip or ip == "0.0.0.0":
            ip = ""
        return Evenement(quand=_date(b["timestamp"]), type="dhcp", donnees={
            "mac": str(d.get("client_mac", "")).lower(), "nom": str(d.get("hostname", "") or ""), "ip": ip,
        }, **commun)
    if genre == "tls":
        nom = b.get("tls", {}).get("sni")
        if nom:
            return Evenement(quand=_date(b["timestamp"]), type="nom", donnees={"nom": str(nom)}, **commun)
        return None
    if genre == "http":
        nom = b.get("http", {}).get("hostname")
        if nom:
            return Evenement(quand=_date(b["timestamp"]), type="nom", donnees={"nom": str(nom)}, **commun)
        return None
    return None


# États de connexion Zeek qui prouvent que le serveur a accepté la connexion
_ZEEK_ETABLI = {"S1", "SF", "S2", "S3", "RSTO", "RSTR"}


def lire_ligne_zeek(ligne: str, journal: str) -> Evenement | None:
    """``journal`` vaut ``conn``, ``dns`` ou ``dhcp`` (nom du fichier Zeek)."""
    ligne = ligne.strip()
    if not ligne or ligne.startswith("#"):
        return None
    try:
        b = json.loads(ligne)
        if not isinstance(b, dict):
            return None
        return _depuis_zeek(b, journal)
    except (KeyError, TypeError, ValueError):
        return None


def _depuis_zeek(b: dict, journal: str) -> Evenement | None:
    if journal == "dhcp":
        return Evenement(quand=float(b["ts"]), type="dhcp", donnees={
            "mac": str(b.get("mac", "")).lower(), "nom": str(b.get("host_name", "") or ""),
            "ip": str(b.get("assigned_addr") or b.get("client_addr") or ""),
        })
    if journal not in ("conn", "dns"):
        return None
    commun = dict(
        quand=float(b["ts"]), ip_src=b["id.orig_h"], ip_dst=b["id.resp_h"],
        port_src=int(b.get("id.orig_p", 0)), port_dst=int(b.get("id.resp_p", 0)),
        proto=str(b.get("proto", "")).upper(),
    )
    if journal == "conn":
        etat = b.get("conn_state", "")
        if commun["proto"] == "TCP":
            etabli = etat in _ZEEK_ETABLI
        else:
            etabli = int(b.get("resp_ip_bytes", b.get("resp_bytes", 0)) or 0) > 0
        mac_src, mac_dst = b.get("orig_l2_addr"), b.get("resp_l2_addr")
        return Evenement(
            type="flux", etabli=etabli, app=str(b.get("service", "") or ""),
            octets_envoyes=int(b.get("orig_ip_bytes", b.get("orig_bytes", 0)) or 0),
            octets_recus=int(b.get("resp_ip_bytes", b.get("resp_bytes", 0)) or 0),
            mac_src=mac_src.lower() if mac_src else None, mac_dst=mac_dst.lower() if mac_dst else None,
            **commun,
        )
    question = str(b.get("query", ""))
    reponses = [(question, r) for r in (b.get("answers") or []) if _est_ip(r)]
    return Evenement(type="dns", donnees={"question": question, "reponses": reponses}, **commun)


def _est_ip(texte: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(texte)
        return True
    except ValueError:
        return False
