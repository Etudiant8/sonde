"""Comptes de l'interface web (besoin F19) : mot de passe fort, hachage scrypt, verrouillage."""
from __future__ import annotations

import hashlib
import hmac
import os
import re

from .config import Config
from .stockage import Base

LONGUEUR_MIN = 12
_N, _R, _P = 2 ** 15, 8, 1
_IDENTIFIANT = re.compile(r"^[a-z0-9._-]{2,40}$")
_TROP_COURANTS = ("motdepasse", "password", "azerty", "qwerty", "123456", "admin", "sonde", "soleil", "reunion")


class MotDePasseRefuse(ValueError):
    """Le mot de passe proposé est trop faible ; le message dit pourquoi."""


def _controler(identifiant: str, mot_de_passe: str) -> None:
    bas = mot_de_passe.lower()
    if len(mot_de_passe) < LONGUEUR_MIN:
        raise MotDePasseRefuse(f"Le mot de passe doit contenir au moins {LONGUEUR_MIN} caractères.")
    if len(mot_de_passe) > 200:
        raise MotDePasseRefuse("Le mot de passe est trop long (200 caractères au maximum).")
    if mot_de_passe.isdigit():
        raise MotDePasseRefuse("Le mot de passe ne peut pas être composé uniquement de chiffres.")
    if len(set(bas)) < 6:
        raise MotDePasseRefuse("Le mot de passe répète trop les mêmes caractères.")
    if identifiant and identifiant.lower() in bas:
        raise MotDePasseRefuse("Le mot de passe ne doit pas contenir l'identifiant.")
    if any(mot in bas for mot in _TROP_COURANTS):
        raise MotDePasseRefuse("Le mot de passe contient un mot trop courant.")


def _hacher(mot_de_passe: str, sel: bytes | None = None, n: int = _N, r: int = _R, p: int = _P) -> str:
    sel = sel or os.urandom(16)
    empreinte = hashlib.scrypt(mot_de_passe.encode("utf-8"), salt=sel, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${r}${p}${sel.hex()}${empreinte.hex()}"


def _correspond(mot_de_passe: str, hachage: str) -> bool:
    try:
        _, n, r, p, sel, _ = hachage.split("$")
        recalcule = _hacher(mot_de_passe, bytes.fromhex(sel), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(recalcule, hachage)


_LEURRE = _hacher("leurre-pour-egaliser-le-temps-de-reponse")


def creer_utilisateur(base: Base, identifiant: str, mot_de_passe: str) -> None:
    identifiant = identifiant.strip().lower()
    if not _IDENTIFIANT.match(identifiant):
        raise ValueError("Identifiant invalide : 2 à 40 lettres minuscules, chiffres, points ou tirets.")
    _controler(identifiant, mot_de_passe)
    if base.un("SELECT 1 FROM utilisateurs WHERE identifiant=?", (identifiant,)):
        raise ValueError(f"L'identifiant « {identifiant} » existe déjà.")
    base.executer("INSERT INTO utilisateurs(identifiant, hachage) VALUES(?, ?)", (identifiant, _hacher(mot_de_passe)))


def changer_mot_de_passe(base: Base, identifiant: str, nouveau: str) -> None:
    identifiant = identifiant.strip().lower()
    if not base.un("SELECT 1 FROM utilisateurs WHERE identifiant=?", (identifiant,)):
        raise KeyError(f"Compte « {identifiant} » inconnu")
    _controler(identifiant, nouveau)
    base.executer("UPDATE utilisateurs SET hachage=?, essais=0, verrou_jusqu=0 WHERE identifiant=?",
                  (_hacher(nouveau), identifiant))


def verifier(base: Base, config: Config, identifiant: str, mot_de_passe: str, maintenant: float) -> bool:
    """Vrai si la connexion est acceptée. Après trop d'essais ratés, le compte est verrouillé."""
    identifiant = (identifiant or "").strip().lower()
    compte = base.un("SELECT * FROM utilisateurs WHERE identifiant=?", (identifiant,))
    if compte is None:
        _correspond(mot_de_passe or "", _LEURRE)     # même temps de réponse qu'un compte existant
        return False
    if maintenant < compte["verrou_jusqu"]:
        return False
    if _correspond(mot_de_passe or "", compte["hachage"]):
        base.executer("UPDATE utilisateurs SET essais=0, verrou_jusqu=0 WHERE id=?", (compte["id"],))
        return True
    essais = compte["essais"] + 1
    if essais >= config.web_verrouillage_essais:
        base.executer("UPDATE utilisateurs SET essais=0, verrou_jusqu=? WHERE id=?",
                      (maintenant + config.web_verrouillage_minutes * 60, compte["id"]))
    else:
        base.executer("UPDATE utilisateurs SET essais=? WHERE id=?", (essais, compte["id"]))
    return False
