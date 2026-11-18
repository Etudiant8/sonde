"""F20 (courriel) et F21 (export JSON / syslog vers le SOC d'un partenaire)."""
import json
import os
import socket
import threading

import pytest

from sonde.alertes import ELEVEE, FAIBLE, MOYENNE
from sonde.export import Exporteur
from sonde.notification import Notificateur, envoyer_smtp
from sonde.traitement import Sonde

from .conftest import T0


@pytest.fixture
def config(config, tmp_path):
    config.dossier_donnees = str(tmp_path / "donnees")
    config.journal_eve = str(tmp_path / "eve-*.json")
    config.nom_client = "Cabinet Hoarau"
    config.smtp_serveur = "smtp.exemple.invalid"
    config.courriel_expediteur = "sonde@exemple.invalid"
    config.courriel_destinataires = ["dirigeant@exemple.invalid"]
    return config


@pytest.fixture
def sonde(config):
    s = Sonde(config)
    s.inventaire.voir("192.168.1.10", T0, mac="00:11:22:33:44:10", nom="PC-COMPTA")
    yield s
    s.fermer()


def pc(sonde):
    return sonde.inventaire.appareil_de("192.168.1.10")


def attaque(sonde, quand=T0, gravite=ELEVEE, sid="1"):
    return sonde.journal.signaler("signature", pc(sonde), sid, gravite, quand, {"signature": "ET MALWARE test", "tiers": "203.0.113.66"})


# ---------------------------------------------------------------- courriel

def test_courriel_pour_un_incident_eleve(sonde, config):
    recus = []
    notif = Notificateur(config, envoyer=recus.append)
    attaque(sonde)
    notif(sonde, T0 + 1)
    assert len(recus) == 1
    m = recus[0]
    assert m["To"] == "dirigeant@exemple.invalid" and m["From"] == "sonde@exemple.invalid"
    assert "Cabinet Hoarau" in m["Subject"] and "élevée" in m["Subject"]
    corps = m.get_content()
    assert "PC-COMPTA" in corps and "attaque connue" in corps and "Débranchez" in corps


def test_pas_de_courriel_pour_les_gravites_inferieures(sonde, config):
    recus = []
    notif = Notificateur(config, envoyer=recus.append)
    attaque(sonde, gravite=MOYENNE)
    notif(sonde, T0 + 1)
    assert recus == []


def test_un_seul_courriel_par_incident(sonde, config):
    recus = []
    notif = Notificateur(config, envoyer=recus.append)
    attaque(sonde)
    notif(sonde, T0 + 1)
    attaque(sonde, quand=T0 + 60)       # la même alerte se répète
    notif(sonde, T0 + 61)
    assert len(recus) == 1


def test_courriel_quand_un_incident_devient_eleve(sonde, config):
    recus = []
    notif = Notificateur(config, envoyer=recus.append)
    attaque(sonde, gravite=MOYENNE)
    notif(sonde, T0 + 1)
    sonde.journal.signaler("balayage", pc(sonde), "port:445", MOYENNE, T0 + 60, {"port": 445, "machines": 15})
    notif(sonde, T0 + 61)               # deux signaux différents : gravité élevée
    assert len(recus) == 1


def test_envoi_rate_reessaye_au_cycle_suivant(sonde, config):
    essais = []

    def capricieux(message):
        essais.append(message)
        if len(essais) == 1:
            raise OSError("serveur injoignable")

    notif = Notificateur(config, envoyer=capricieux)
    attaque(sonde)
    notif(sonde, T0 + 1)                # échec, sans faire planter la sonde
    notif(sonde, T0 + 31)               # réussite
    notif(sonde, T0 + 61)               # plus rien à envoyer
    assert len(essais) == 2


def test_sans_reglage_smtp_aucun_envoi(sonde, config):
    config.smtp_serveur = ""
    recus = []
    attaque(sonde)
    Notificateur(config, envoyer=recus.append)(sonde, T0 + 1)
    assert recus == []


def test_incident_ferme_non_notifie(sonde, config):
    recus = []
    attaque(sonde)
    sonde.journal.resoudre(sonde.journal.incidents()[0]["id"])
    Notificateur(config, envoyer=recus.append)(sonde, T0 + 1)
    assert recus == []


def test_objet_sans_retour_a_la_ligne(sonde, config):
    """Un nom d'appareil piégé ne doit pas pouvoir injecter d'en-têtes dans le courriel."""
    sonde.inventaire.nommer(pc(sonde), "PC\r\nBcc: pirate@exemple.invalid")
    recus = []
    attaque(sonde)
    Notificateur(config, envoyer=recus.append)(sonde, T0 + 1)
    assert len(recus) == 1 and recus[0]["Bcc"] is None and "\n" not in recus[0]["Subject"]


def test_envoi_smtp_chiffre_et_authentifie(config, monkeypatch):
    appels = []

    class FauxSMTP:
        def __init__(self, hote, port, timeout):
            appels.append(("connexion", hote, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            appels.append(("starttls", context is not None))

        def login(self, utilisateur, mot_de_passe):
            appels.append(("login", utilisateur))

        def send_message(self, message):
            appels.append(("envoi", message["Subject"]))

    monkeypatch.setattr("smtplib.SMTP", FauxSMTP)
    config.smtp_utilisateur, config.smtp_mot_de_passe = "sonde", "secret"
    from email.message import EmailMessage

    m = EmailMessage(); m["Subject"] = "essai"
    envoyer_smtp(config, m)
    assert appels == [("connexion", "smtp.exemple.invalid", 587), ("starttls", True), ("login", "sonde"), ("envoi", "essai")]


# ------------------------------------------------------------------ export

def test_export_fichier_json(sonde, config, tmp_path):
    config.export_fichier = str(tmp_path / "export" / "alertes.json")
    export = Exporteur(config)
    attaque(sonde)
    sonde.journal.signaler("non_chiffre", pc(sonde), "23", FAIBLE, T0, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    export(sonde, T0 + 1)
    lignes = [json.loads(l) for l in open(config.export_fichier, encoding="utf-8")]
    assert len(lignes) == 2
    a = [l for l in lignes if l["type"] == "signature"][0]
    assert a["client"] == "Cabinet Hoarau" and a["gravite"] == "élevée" and a["categorie"] == "incident"
    assert a["appareil"] == {"nom": "PC-COMPTA", "adresses": ["192.168.1.10"], "mac": "00:11:22:33:44:10"}
    assert a["horodatage"] == "2026-05-28T20:26:40+00:00" and a["detail"]["signature"] == "ET MALWARE test"
    assert "attaque connue" in a["texte"] and a["incident"] == sonde.journal.incidents()[0]["id"]
    assert (os.stat(config.export_fichier).st_mode & 0o077) == 0


def test_export_une_seule_fois_sauf_mise_a_jour(sonde, config, tmp_path):
    config.export_fichier = str(tmp_path / "alertes.json")
    export = Exporteur(config)
    attaque(sonde)
    export(sonde, T0 + 1)
    export(sonde, T0 + 2)
    assert len(open(config.export_fichier).readlines()) == 1
    attaque(sonde, quand=T0 + 60)        # l'alerte se répète : le SOC reçoit la mise à jour
    export(sonde, T0 + 61)
    lignes = [json.loads(l) for l in open(config.export_fichier)]
    assert len(lignes) == 2 and lignes[1]["nombre"] == 2


def test_export_syslog_udp(sonde, config):
    recepteur = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recepteur.bind(("127.0.0.1", 0)); recepteur.settimeout(3)
    config.export_syslog_hote, config.export_syslog_port = "127.0.0.1", recepteur.getsockname()[1]
    attaque(sonde)
    Exporteur(config)(sonde, T0 + 1)
    message = recepteur.recv(65535).decode("utf-8")
    recepteur.close()
    # RFC 5424 : priorité local0.crit = 16*8+2 = 130, version 1
    assert message.startswith("<130>1 2026-05-28T20:26:40+00:00 ")
    entete, _, charge = message.partition(" - - - ")
    assert " sonde" in entete and json.loads(charge)["type"] == "signature"


def test_export_syslog_tcp(sonde, config):
    serveur = socket.socket(); serveur.bind(("127.0.0.1", 0)); serveur.listen(1)
    recu = []

    def ecoute():
        cx, _ = serveur.accept()
        cx.settimeout(3)
        donnees = b""
        while not donnees.endswith(b"\n"):
            bloc = cx.recv(65535)
            if not bloc:
                break
            donnees += bloc
        recu.append(donnees); cx.close()

    fil = threading.Thread(target=ecoute); fil.start()
    config.export_syslog_hote, config.export_syslog_port = "127.0.0.1", serveur.getsockname()[1]
    config.export_syslog_protocole = "tcp"
    attaque(sonde, gravite=MOYENNE)
    Exporteur(config)(sonde, T0 + 1)
    fil.join(5); serveur.close()
    assert recu and recu[0].startswith(b"<132>1 ") and recu[0].endswith(b"\n")     # local0.warning


def test_export_syslog_injoignable_reessaye(sonde, config):
    config.export_syslog_hote, config.export_syslog_port, config.export_syslog_protocole = "127.0.0.1", 9, "tcp"
    attaque(sonde)
    Exporteur(config)(sonde, T0 + 1)                    # ne plante pas
    assert sonde.base.un("SELECT exportee FROM alertes")["exportee"] == 0      # sera renvoyée plus tard


def test_sans_export_configure_rien_n_est_marque(sonde, config):
    attaque(sonde)
    Exporteur(config)(sonde, T0 + 1)
    assert sonde.base.un("SELECT exportee FROM alertes")["exportee"] == 0


def test_branchement_sur_le_cycle(config, tmp_path):
    from sonde.traitement import construire

    config.export_fichier = str(tmp_path / "alertes.json")
    s = construire(config)
    assert {type(a).__name__ for a in s.apres_cycle} == {"Notificateur", "Exporteur"}
    s.fermer()
