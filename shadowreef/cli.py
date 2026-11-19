"""Ligne de commande de la sonde.

    shadowreef --config /etc/shadowreef/shadowreef.toml surveiller
"""
from __future__ import annotations

import argparse
import getpass
import glob
import logging
import os
import shutil
import signal
import sys
import time

from . import __version__
from .comptes import MotDePasseRefuse, changer_mot_de_passe, creer_utilisateur
from .config import Config, charger

CONFIG_PAR_DEFAUT = "/etc/shadowreef/shadowreef.toml"


def _erreur(message: str) -> int:
    print(f"Erreur : {message}", file=sys.stderr)
    return 2


def _mot_de_passe() -> str:
    """Lu dans SHADOWREEF_MOT_DE_PASSE (installation automatisée) ou saisi deux fois, sans affichage."""
    depuis_env = os.environ.get("SHADOWREEF_MOT_DE_PASSE")
    if depuis_env is not None:
        return depuis_env
    premier = getpass.getpass("Mot de passe (12 caractères au moins) : ")
    if premier != getpass.getpass("Encore une fois : "):
        raise MotDePasseRefuse("Les deux saisies sont différentes.")
    return premier


def _base(config: Config):
    from .stockage import Base

    base = Base(config.chemin_base)
    base.initialiser()
    return base


# ------------------------------------------------------------------ commandes

def cmd_initialiser(config: Config, args) -> int:
    _base(config).fermer()
    print(f"Base prête : {config.chemin_base}")
    return 0


def cmd_verifier_config(config: Config, args) -> int:
    print(f"Réglages valides pour « {config.nom_client} ».")
    print(f"  journaux lus     : {config.journal_eve}")
    print(f"  données          : {config.dossier_donnees}")
    print(f"  apprentissage    : {config.apprentissage_heures} h")
    print(f"  courriel         : {'activé' if config.smtp_serveur and config.courriel_destinataires else 'désactivé'}")
    print(f"  export           : {'activé' if config.export_fichier or config.export_syslog_hote else 'désactivé'}")
    return 0


def cmd_creer_compte(config: Config, args) -> int:
    base = _base(config)
    try:
        creer_utilisateur(base, args.identifiant, _mot_de_passe())
    except ValueError as erreur:
        return _erreur(str(erreur))
    finally:
        base.fermer()
    print(f"Compte « {args.identifiant.strip().lower()} » créé.")
    return 0


def cmd_mot_de_passe(config: Config, args) -> int:
    base = _base(config)
    try:
        changer_mot_de_passe(base, args.identifiant, _mot_de_passe())
    except KeyError:
        return _erreur(f"compte « {args.identifiant} » inconnu.")
    except ValueError as erreur:
        return _erreur(str(erreur))
    finally:
        base.fermer()
    print("Mot de passe changé.")
    return 0


def cmd_cycle(config: Config, args) -> int:
    from .traitement import construire

    sonde = construire(config)
    try:
        bilan = sonde.cycle()
    finally:
        sonde.fermer()
    print(f"{bilan['evenements']} événements traités, {bilan['lignes_ignorees']} lignes ignorées.")
    return 0


def cmd_surveiller(config: Config, args) -> int:
    from .traitement import construire

    journal = logging.getLogger("shadowreef")
    sonde = construire(config)
    arret = {"demande": False}

    def demander_arret(signum, frame):
        arret["demande"] = True

    for signal_arret in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(signal_arret, demander_arret)
        except ValueError:          # hors du fil principal (tests)
            pass
    journal.info("Shadowreef %s démarré pour « %s »", __version__, config.nom_client)
    fait = 0
    try:
        while not arret["demande"]:
            try:
                bilan = sonde.cycle()
                if bilan["evenements"]:
                    journal.info("%d événements traités", bilan["evenements"])
            except Exception:       # une panne passagère ne doit pas arrêter la surveillance
                journal.exception("Cycle interrompu, nouvelle tentative au prochain cycle")
            fait += 1
            if args.cycles and fait >= args.cycles:
                break
            fin = time.monotonic() + args.intervalle
            while time.monotonic() < fin and not arret["demande"]:
                time.sleep(min(0.5, max(0.0, fin - time.monotonic())))
    finally:
        sonde.fermer()
    journal.info("Shadowreef arrêté")
    return 0


def cmd_etat(config: Config, args) -> int:
    from .traitement import Sonde

    sonde = Sonde(config)
    try:
        sante = sonde.sante()
        etat = sonde.journal.etat_general()
    finally:
        sonde.fermer()
    silence = sante["dernier_trafic_il_y_a"]
    print(f"Shadowreef {sante['version']} - état général : {etat}")
    print(f"  {sante['appareils']} appareils, {sante['incidents_ouverts']} incident(s) en cours")
    print("  dernier trafic   : " + ("jamais" if silence is None else f"il y a {silence} s"))
    print("  apprentissage    : " + ("en cours" if sante["apprentissage"] else "terminé"))
    if sante["muette"]:
        print("  ATTENTION : la sonde ne reçoit pas de trafic.")
        return 1
    return 0


def cmd_rapport(config: Config, args) -> int:
    from .rapport import generer_rapport
    from .traitement import Sonde

    sonde = Sonde(config)
    try:
        maintenant = time.time()
        generer_rapport(sonde, args.sortie, maintenant - args.jours * 86400, maintenant, maintenant)
    finally:
        sonde.fermer()
    print(f"Rapport écrit : {args.sortie}")
    return 0


def cmd_effacer_donnees(config: Config, args) -> int:
    """Supprime tout ce que la sonde a enregistré chez le client (N12)."""
    if not args.confirmer:
        return _erreur("cette commande efface toutes les données ; ajoutez --confirmer pour continuer.")
    cibles = glob.glob(config.journal_eve)
    if config.export_fichier:
        cibles.append(config.export_fichier)
    for chemin in cibles:
        try:
            os.remove(chemin)
        except OSError:
            pass
    if os.path.isdir(config.dossier_donnees):
        for nom in os.listdir(config.dossier_donnees):
            chemin = os.path.join(config.dossier_donnees, nom)
            shutil.rmtree(chemin) if os.path.isdir(chemin) else os.remove(chemin)
    print("Données de la sonde effacées.")
    return 0


def arguments_gunicorn(args) -> list[str]:
    commande = ["gunicorn", "--bind", args.adresse, "--workers", "1", "--threads", "4",
                "--access-logfile", "-", "--worker-tmp-dir", "/tmp"]
    if args.certificat and args.cle:
        commande += ["--certfile", args.certificat, "--keyfile", args.cle]
    return commande + ["shadowreef.web:application()"]


def cmd_web(config: Config, args) -> int:
    if not (args.certificat and args.cle) and not args.sans_tls:
        return _erreur("l'interface exige HTTPS : indiquez --certificat et --cle (ou --sans-tls derrière un relais HTTPS).")
    os.environ["SHADOWREEF_CONFIG"] = args.config
    commande = arguments_gunicorn(args)
    executable = os.path.join(os.path.dirname(sys.executable), "gunicorn")
    os.execv(executable if os.path.isfile(executable) else shutil.which("gunicorn") or "gunicorn", commande)
    return 0  # jamais atteint


# ----------------------------------------------------------------------- main

def _analyseur() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shadowreef", description="Shadowreef : sonde de détection réseau installée chez le client.")
    p.add_argument("--version", action="version", version=f"shadowreef {__version__}")
    p.add_argument("--config", default=os.environ.get("SHADOWREEF_CONFIG", CONFIG_PAR_DEFAUT),
                   help=f"fichier de réglages (défaut : {CONFIG_PAR_DEFAUT})")
    s = p.add_subparsers(dest="commande", required=True, metavar="commande")
    s.add_parser("initialiser", help="crée la base de données").set_defaults(action=cmd_initialiser)
    s.add_parser("verifier-config", help="contrôle le fichier de réglages").set_defaults(action=cmd_verifier_config)
    c = s.add_parser("creer-compte", help="crée un compte pour l'interface web")
    c.add_argument("identifiant"); c.set_defaults(action=cmd_creer_compte)
    c = s.add_parser("mot-de-passe", help="change le mot de passe d'un compte")
    c.add_argument("identifiant"); c.set_defaults(action=cmd_mot_de_passe)
    s.add_parser("cycle", help="lit les nouveaux journaux une fois").set_defaults(action=cmd_cycle)
    c = s.add_parser("surveiller", help="surveille en continu")
    c.add_argument("--intervalle", type=float, default=30.0, help="secondes entre deux lectures (défaut : 30)")
    c.add_argument("--cycles", type=int, default=0, help="s'arrête après N lectures (0 = jamais)")
    c.set_defaults(action=cmd_surveiller)
    s.add_parser("etat", help="affiche l'état de la sonde (code 1 si elle ne reçoit rien)").set_defaults(action=cmd_etat)
    c = s.add_parser("rapport", help="écrit le rapport PDF")
    c.add_argument("--jours", type=int, default=30); c.add_argument("--sortie", required=True)
    c.set_defaults(action=cmd_rapport)
    c = s.add_parser("effacer-donnees", help="efface toutes les données enregistrées chez le client")
    c.add_argument("--confirmer", action="store_true"); c.set_defaults(action=cmd_effacer_donnees)
    c = s.add_parser("web", help="lance l'interface web (HTTPS)")
    c.add_argument("--adresse", default="0.0.0.0:8443")
    c.add_argument("--certificat"); c.add_argument("--cle")
    c.add_argument("--sans-tls", action="store_true", help="uniquement derrière un relais HTTPS")
    c.set_defaults(action=cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _analyseur().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")
    try:
        config = charger(args.config) if os.path.exists(args.config) or args.config != CONFIG_PAR_DEFAUT else Config()
    except FileNotFoundError:
        return _erreur(f"fichier de réglages introuvable : {args.config}")
    except (ValueError, OSError) as erreur:
        return _erreur(f"réglages invalides ({args.config}) : {erreur}")
    return args.action(config, args)
