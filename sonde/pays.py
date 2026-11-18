"""Pays d'une adresse IP, à partir d'un fichier CSV local « début,fin,pays ».

Le fichier gratuit « IP to Country Lite » de DB-IP a ce format. Aucune requête
n'est envoyée sur Internet : la recherche se fait dans le fichier (N11).
"""
from __future__ import annotations

import bisect
import csv
import ipaddress
from pathlib import Path
from typing import Callable


def charger_pays(chemin: str) -> Callable[[str], str | None] | None:
    if not chemin or not Path(chemin).is_file():
        return None
    debuts: list[int] = []
    plages: list[tuple[int, int, str]] = []
    with open(chemin, newline="", encoding="utf-8", errors="replace") as f:
        for ligne in csv.reader(f):
            try:
                debut, fin = ipaddress.ip_address(ligne[0].strip()), ipaddress.ip_address(ligne[1].strip())
                pays = ligne[2].strip().upper()
            except (ValueError, IndexError):
                continue
            # les adresses IPv6 sont décalées pour ne pas se mélanger aux IPv4
            decalage = 1 << 130 if debut.version == 6 else 0
            plages.append((int(debut) + decalage, int(fin) + decalage, pays))
    plages.sort()
    debuts = [p[0] for p in plages]

    def pays_de(ip: str) -> str | None:
        try:
            adresse = ipaddress.ip_address(ip)
        except ValueError:
            return None
        valeur = int(adresse) + (1 << 130 if adresse.version == 6 else 0)
        i = bisect.bisect_right(debuts, valeur) - 1
        if i >= 0 and plages[i][0] <= valeur <= plages[i][1]:
            return plages[i][2]
        return None

    return pays_de
