"""Intégration : capture réseau -> vrai Suricata (avec nos réglages) -> sonde -> incidents.

Ce test ne s'exécute que si Suricata est installé sur la machine.
"""
import fnmatch
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from shadowreef.alertes import ELEVEE
from shadowreef.config import Config
from shadowreef.traitement import Sonde

from .conftest import T0

RACINE = Path(__file__).parent.parent
pytestmark = pytest.mark.integration


def test_nom_des_journaux_coherent_avec_suricata():
    """Le motif lu par la sonde doit correspondre au nom de fichier que Suricata écrit."""
    reglages = (RACINE / "deploiement" / "suricata" / "shadowreef.yaml").read_text()
    assert "filename: eve-%Y-%m-%d.json" in reglages
    assert fnmatch.fnmatch("/var/log/suricata/eve-2026-05-28.json", Config().journal_eve)


@pytest.fixture(scope="module")
def journaux_suricata(tmp_path_factory):
    if not shutil.which("suricata") or not os.path.isfile("/etc/suricata/suricata.yaml"):
        pytest.skip("Suricata n'est pas installé")
    from tests.outils.fabrique_pcap import scenario
    from scapy.all import wrpcap

    travail = tmp_path_factory.mktemp("suricata")
    capture = travail / "scenario.pcap"
    wrpcap(str(capture), scenario().paquets)
    # même montage que dans l'image Docker : configuration standard + nos réglages inclus à la fin
    config = travail / "suricata.yaml"
    config.write_text(Path("/etc/suricata/suricata.yaml").read_text()
                      + f"\ninclude: {RACINE / 'deploiement' / 'suricata' / 'shadowreef.yaml'}\n")
    sortie = travail / "journaux"; sortie.mkdir()
    resultat = subprocess.run(
        ["suricata", "-c", str(config), "-r", str(capture), "-l", str(sortie), "-k", "none",
         "-S", str(RACINE / "tests" / "echantillons" / "regles_test.rules")],
        capture_output=True, text=True, timeout=120)
    assert resultat.returncode == 0, resultat.stderr[-2000:]
    return sortie


def test_suricata_ecrit_un_journal_par_jour(journaux_suricata):
    fichiers = os.listdir(journaux_suricata)
    assert any(fnmatch.fnmatch(f, "eve-????-??-??.json") for f in fichiers), fichiers


def test_de_la_capture_aux_incidents(journaux_suricata, tmp_path):
    config = Config()
    config.dossier_donnees = str(tmp_path / "donnees")
    config.dossier_journaux = str(journaux_suricata)
    config.journal_eve = str(journaux_suricata / "eve-*.json")
    sonde = Sonde(config)
    try:
        bilan = sonde.cycle(T0 + 60)
        assert bilan["evenements"] >= 25 and bilan["lignes_ignorees"] == 0
        inv, journal = sonde.inventaire, sonde.journal

        compta = inv.appareil(inv.appareil_de("192.168.1.10"))
        assert compta["nom_reseau"] == "PC-COMPTA" and compta["mac"] == "00:11:22:33:44:10"
        assert len(inv.lister()) == 5

        ouverts = {i["appareil_id"]: i for i in journal.incidents(etat="ouvert")}
        assert ouverts[inv.appareil_de("192.168.1.10")]["gravite"] == ELEVEE
        assert "15 machines" in ouverts[inv.appareil_de("192.168.1.66")]["resume"]
        assert {(f["type"], f["detail"]["port"]) for f in journal.faiblesses()} == {
            ("non_chiffre", 23), ("service_expose", 3389)}
        # le nom du site vu en HTTP est retenu pour expliquer les destinations
        assert sonde.base.un("SELECT nom FROM noms_dns WHERE ip='203.0.113.66'")["nom"] == "mauvais.example"
    finally:
        sonde.fermer()
