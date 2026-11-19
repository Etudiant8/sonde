"""Explications en français clair (besoin F15).

Chaque type d'alerte a une phrase qui dit ce qui s'est passé et une action
recommandée, écrites pour un dirigeant qui n'est pas informaticien.
"""
from __future__ import annotations

from typing import Callable


def taille(octets: float) -> str:
    """1 536 000 000 -> « 1,5 Go »."""
    for unite, pas in (("Go", 1e9), ("Mo", 1e6), ("ko", 1e3)):
        if octets >= pas:
            valeur = octets / pas
            texte = f"{valeur:.1f}".replace(".", ",") if valeur < 10 else f"{valeur:.0f}"
            return f"{texte} {unite}"
    return f"{int(octets)} octets"


def _signature(nom: str, d: dict) -> str:
    tiers = f", lors d'un échange avec {d['tiers']}" if d.get("tiers") else ""
    regle = d.get("signature", "règle inconnue")
    gravite = d.get("_gravite", 3)
    if gravite >= 3:
        return f"Une activité correspondant à une attaque connue a été repérée sur {nom}{tiers} : « {regle} »"
    if gravite == 2:
        return f"Une activité suspecte a été repérée sur {nom}{tiers} : « {regle} »"
    return f"Une règle de surveillance de faible importance s'est déclenchée sur {nom}{tiers} : « {regle} »"


def _balayage(nom: str, d: dict) -> str:
    if d.get("machines"):
        return (f"{nom} a tenté de joindre {d['machines']} machines du réseau sur le port {d.get('port')} "
                f"en quelques minutes, ce qui ressemble à une recherche de cibles")
    return (f"{nom} a essayé {d.get('ports')} ports différents sur la machine {d.get('cible')}, "
            f"ce qui ressemble à une recherche de failles")


def _sortie(nom: str, d: dict) -> str:
    habituel = f", contre {taille(d['habituel'])} habituellement" if d.get("habituel") else ""
    vers = f", surtout vers {d['destination']}" if d.get("destination") else ""
    return f"{nom} a envoyé {taille(d.get('octets', 0))} vers Internet dans la journée{habituel}{vers}"


def _destination(nom: str, d: dict) -> str:
    return (f"{nom} s'est connecté directement à l'adresse {d.get('ip')} sur le port {d.get('port')}, "
            f"une destination jamais vue et sans nom de site associé")


def _pays(nom: str, d: dict) -> str:
    return f"{nom} a communiqué pour la première fois avec un pays inhabituel ({d.get('pays')}), adresse {d.get('ip')}"


def _hors_heures(nom: str, d: dict) -> str:
    return (f"{nom} a envoyé {taille(d.get('octets', 0))} vers Internet en dehors des heures de travail, "
            f"ce qu'il ne fait pas d'habitude")


def _expose(nom: str, d: dict) -> str:
    service = f" ({d['service']})" if d.get("service") else ""
    return f"{nom} accepte des connexions venues d'Internet sur le port {d.get('port')}{service}"


def _non_chiffre(nom: str, d: dict) -> str:
    return (f"{nom} utilise {d.get('protocole', 'un protocole')} (port {d.get('port')}), "
            f"qui fait circuler les mots de passe en clair sur le réseau")


MODELES: dict[str, tuple[Callable[[str, dict], str], str]] = {
    "signature": (_signature,
                  "Débranchez cet appareil du réseau et faites-le vérifier par votre informaticien"),
    "balayage": (_balayage,
                 "Vérifiez qui utilise cet appareil ; si personne n'a lancé d'outil d'inventaire, débranchez-le et faites-le examiner"),
    "sortie_volume": (_sortie,
                      "Vérifiez si une sauvegarde ou un gros envoi était prévu ; sinon, faites contrôler l'appareil"),
    "destination_inhabituelle": (_destination,
                                 "Demandez à l'utilisateur quel logiciel il a lancé ; en cas de doute, faites analyser le poste"),
    "nouveau_pays": (_pays,
                     "Vérifiez si un logiciel ou un service utilisé récemment explique cette destination"),
    "hors_heures": (_hors_heures,
                    "Vérifiez si quelqu'un travaillait ou si une sauvegarde était programmée à ce moment-là"),
    "nouvel_appareil": (lambda nom, d: f"Un nouvel appareil est apparu sur le réseau : {nom}",
                        "Identifiez cet appareil ; s'il vous appartient, marquez-le comme connu, sinon débranchez-le"),
    "sonde_muette": (lambda nom, d: f"La sonde ne voit plus aucun trafic depuis {d.get('minutes')} minutes : le réseau n'est plus surveillé",
                     "Vérifiez le câble relié au port miroir et que la machine de la sonde est allumée"),
    "service_expose": (_expose,
                       "Si cet accès n'est pas voulu, fermez-le sur la box ou le pare-feu ; sinon, protégez-le par un VPN"),
    "non_chiffre": (_non_chiffre,
                    "Remplacez ce service par son équivalent chiffré (SSH, SFTP, IMAPS...) ou désactivez-le"),
}

TYPES = tuple(MODELES)


CONSEILS_SIGNATURE = {
    3: "Débranchez cet appareil du réseau et faites-le vérifier par votre informaticien",
    2: "Faites vérifier cet appareil par votre informaticien dans les prochains jours",
    1: "Aucune action immédiate ; parlez-en à votre informaticien si cela se répète",
}


def phrase(type_alerte: str, nom: str, detail: dict, gravite: int = 3) -> str:
    return MODELES[type_alerte][0](nom, {**detail, "_gravite": gravite})


def conseil(type_alerte: str, gravite: int = 3) -> str:
    """Action recommandée, adaptée à la gravité pour les règles de signature."""
    if type_alerte == "signature":
        return CONSEILS_SIGNATURE.get(gravite, CONSEILS_SIGNATURE[3]) + "."
    return MODELES[type_alerte][1] + "."


def expliquer(alertes: list[dict], nom: str) -> tuple[str, str]:
    """Résumé et action d'un incident, à partir de ses alertes (la plus grave d'abord)."""
    # la plus grave d'abord ; à gravité égale, l'arrivée d'un appareil passe après ce qu'il fait
    ordre = sorted(alertes, key=lambda a: (-a["gravite"], a["type"] == "nouvel_appareil", a["premiere_vue"]))
    phrases = []
    for a in ordre:
        texte = phrase(a["type"], nom, a["detail"], a["gravite"])
        if a["type"] == "signature" and a.get("nombre", 1) > 1:
            texte += f" ({a['nombre']} fois)"
        phrases.append(texte + ".")
    resume = phrases[0]
    if len(phrases) > 1:
        resume += " Également observé : " + " ".join(_minuscule(p) for p in phrases[1:])
    return resume, conseil(ordre[0]["type"], ordre[0]["gravite"])


def _minuscule(texte: str) -> str:
    """« Un nouvel appareil... » -> « un nouvel appareil... » après deux-points (sauf nom propre ou adresse)."""
    for debut in ("Un ", "Une ", "La "):
        if texte.startswith(debut):
            return texte[0].lower() + texte[1:]
    return texte
