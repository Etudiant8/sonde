"""Inventaire des appareils du réseau (besoins F11 et F12).

Un appareil est identifié par son adresse MAC quand elle est connue, sinon par
son adresse IP. Une même machine peut avoir plusieurs adresses (IPv4, IPv6,
changement DHCP). Une MAC qui porte trop d'adresses est un routeur : les
machines situées derrière sont alors suivies par leur adresse IP.
"""
from __future__ import annotations

from pathlib import Path

from .config import Config
from .stockage import Base

ETIQUETTE_MAX = 80


class Inventaire:
    def __init__(self, base: Base, config: Config) -> None:
        self.base = base
        self.config = config
        self._fabricants = _charger_fabricants(config.fichier_fabricants)

    # ------------------------------------------------------------------ voir
    def voir(self, ip: str, quand: float, mac: str | None = None, nom: str | None = None) -> tuple[int, bool]:
        """Note qu'une adresse interne a été vue. Renvoie (identifiant, est_nouveau)."""
        mac = _mac_propre(mac)
        if mac and self._est_passerelle(mac):
            mac = None
        par_ip = self.base.un("SELECT appareil_id FROM adresses WHERE ip=?", (ip,))
        par_mac = self.base.un("SELECT id FROM appareils WHERE mac=?", (mac,)) if mac else None
        nouveau = False

        if par_mac:
            ident = par_mac["id"]
            if not par_ip or par_ip["appareil_id"] != ident:
                if self._nombre_adresses(ident) >= self.config.passerelle_max_adresses:
                    # trop d'adresses derrière cette MAC : c'est un routeur
                    self.base.executer("UPDATE appareils SET passerelle=1 WHERE id=?", (ident,))
                    return self.voir(ip, quand, None, nom)
                self._attacher(ip, ident, quand)
        elif par_ip:
            ident = par_ip["appareil_id"]
            actuel = self.base.un("SELECT mac FROM appareils WHERE id=?", (ident,))
            if mac and actuel["mac"] is None:
                self.base.executer("UPDATE appareils SET mac=?, fabricant=? WHERE id=?",
                                   (mac, self._fabricant(mac), ident))
            elif mac and actuel["mac"] != mac:
                # l'adresse a été réattribuée à une autre machine
                ident = self._creer(mac, quand)
                self._attacher(ip, ident, quand)
                nouveau = True
        else:
            ident = self._creer(mac, quand)
            self._attacher(ip, ident, quand)
            nouveau = True

        self.base.executer(
            "UPDATE appareils SET premiere_vue=MIN(premiere_vue, ?), derniere_vue=MAX(derniere_vue, ?) WHERE id=?",
            (quand, quand, ident))
        self.base.executer("UPDATE adresses SET derniere_vue=MAX(derniere_vue, ?) WHERE ip=?", (quand, ip))
        if nom:
            self.base.executer("UPDATE appareils SET nom_reseau=? WHERE id=?", (nom[:ETIQUETTE_MAX], ident))
        return ident, nouveau

    def _creer(self, mac: str | None, quand: float) -> int:
        curseur = self.base.executer(
            "INSERT INTO appareils(mac, fabricant, premiere_vue, derniere_vue) VALUES(?, ?, ?, ?)",
            (mac, self._fabricant(mac), quand, quand))
        return int(curseur.lastrowid)

    def _attacher(self, ip: str, ident: int, quand: float) -> None:
        self.base.executer(
            "INSERT INTO adresses(ip, appareil_id, derniere_vue) VALUES(?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET appareil_id=excluded.appareil_id, derniere_vue=excluded.derniere_vue",
            (ip, ident, quand))

    def _nombre_adresses(self, ident: int) -> int:
        return self.base.un("SELECT COUNT(*) n FROM adresses WHERE appareil_id=?", (ident,))["n"]

    def _est_passerelle(self, mac: str) -> bool:
        ligne = self.base.un("SELECT passerelle FROM appareils WHERE mac=?", (mac,))
        return bool(ligne and ligne["passerelle"])

    def _fabricant(self, mac: str | None) -> str:
        return self._fabricants.get(mac[:8], "") if mac else ""

    # ------------------------------------------------------------- consulter
    def appareil_de(self, ip: str) -> int | None:
        ligne = self.base.un("SELECT appareil_id FROM adresses WHERE ip=?", (ip,))
        return ligne["appareil_id"] if ligne else None

    def appareil(self, ident: int) -> dict | None:
        ligne = self.base.un("SELECT * FROM appareils WHERE id=?", (ident,))
        return self._en_dict(ligne) if ligne else None

    def lister(self) -> list[dict]:
        lignes = self.base.tous("SELECT * FROM appareils ORDER BY derniere_vue DESC, id DESC")
        return [self._en_dict(l) for l in lignes]

    def _en_dict(self, ligne) -> dict:
        adresses = [a["ip"] for a in self.base.tous(
            "SELECT ip FROM adresses WHERE appareil_id=? ORDER BY derniere_vue DESC, ip", (ligne["id"],))]
        d = dict(ligne)
        d["connu"] = bool(d["connu"])
        d["passerelle"] = bool(d["passerelle"])
        d["adresses"] = adresses
        d["nom_affiche"] = d["etiquette"] or d["nom_reseau"] or (adresses[0] if adresses else d["mac"] or f"appareil {d['id']}")
        return d

    # -------------------------------------------------------------- modifier
    def nommer(self, ident: int, etiquette: str) -> None:
        etiquette = " ".join(etiquette.split())
        if len(etiquette) > ETIQUETTE_MAX:
            raise ValueError(f"Nom trop long ({ETIQUETTE_MAX} caractères au maximum)")
        self._existe(ident)
        self.base.executer("UPDATE appareils SET etiquette=? WHERE id=?", (etiquette, ident))

    def marquer_connu(self, ident: int, connu: bool) -> None:
        self._existe(ident)
        self.base.executer("UPDATE appareils SET connu=? WHERE id=?", (1 if connu else 0, ident))

    def _existe(self, ident: int) -> None:
        if not self.base.un("SELECT 1 FROM appareils WHERE id=?", (ident,)):
            raise KeyError(f"Appareil {ident} inconnu")


def _mac_propre(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().lower()
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or len(mac) != 17:
        return None
    try:
        if int(mac[:2], 16) & 1:  # adresse de groupe (multidiffusion) : ce n'est pas une machine
            return None
    except ValueError:
        return None
    return mac


def _charger_fabricants(chemin: str) -> dict[str, str]:
    """Lit un fichier au format « manuf » de Wireshark : préfixe, nom court, nom long."""
    table: dict[str, str] = {}
    if not chemin or not Path(chemin).is_file():
        return table
    for ligne in Path(chemin).read_text(encoding="utf-8", errors="replace").splitlines():
        if not ligne.strip() or ligne.startswith("#"):
            continue
        champs = ligne.split("\t")
        prefixe = champs[0].strip().lower()
        if len(prefixe) == 8 and len(champs) >= 2:
            table[prefixe] = (champs[2] if len(champs) >= 3 and champs[2].strip() else champs[1]).strip()
    return table
