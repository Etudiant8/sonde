"""Ligne de commande : installation, compte, cycle, rapport, état, effacement (N1, N12)."""
import os
import shutil
import subprocess

import pytest

from sonde.cli import main
from sonde.config import Config, charger

from .conftest import T0

BON = "Tamarin-Vanille-2026"


@pytest.fixture
def reglages(tmp_path):
    donnees = tmp_path / "donnees"
    journaux = tmp_path / "journaux"; journaux.mkdir()
    fichier = tmp_path / "sonde.toml"
    fichier.write_text(f'''
nom_client = "Cabinet Hoarau"
dossier_donnees = "{donnees}"
dossier_journaux = "{journaux}"
journal_eve = "{journaux}/eve-*.json"
''')
    return fichier


def lancer(reglages, *arguments, entree=None, env=None, monkeypatch=None):
    return main(["--config", str(reglages), *arguments])


def test_initialiser_cree_la_base(reglages, capsys):
    assert lancer(reglages, "initialiser") == 0
    assert os.path.isfile(charger(reglages).chemin_base)
    assert lancer(reglages, "initialiser") == 0        # sans danger si on recommence


def test_creer_un_compte_par_variable_d_environnement(reglages, monkeypatch, capsys):
    monkeypatch.setenv("SONDE_MOT_DE_PASSE", BON)
    assert lancer(reglages, "creer-compte", "marie") == 0
    assert BON not in capsys.readouterr().out
    from sonde.comptes import verifier
    from sonde.stockage import Base

    base = Base(charger(reglages).chemin_base)
    assert verifier(base, Config(), "marie", BON, T0) is True
    base.fermer()


def test_creer_un_compte_mot_de_passe_faible(reglages, monkeypatch, capsys):
    monkeypatch.setenv("SONDE_MOT_DE_PASSE", "court")
    assert lancer(reglages, "creer-compte", "marie") == 2
    assert "12 caractères" in capsys.readouterr().err


def test_creer_un_compte_saisie_interactive(reglages, monkeypatch):
    monkeypatch.delenv("SONDE_MOT_DE_PASSE", raising=False)
    saisies = iter([BON, BON])
    monkeypatch.setattr("getpass.getpass", lambda invite="": next(saisies))
    assert lancer(reglages, "creer-compte", "marie") == 0


def test_creer_un_compte_saisies_differentes(reglages, monkeypatch, capsys):
    monkeypatch.delenv("SONDE_MOT_DE_PASSE", raising=False)
    saisies = iter([BON, BON + "x"])
    monkeypatch.setattr("getpass.getpass", lambda invite="": next(saisies))
    assert lancer(reglages, "creer-compte", "marie") == 2
    assert "différentes" in capsys.readouterr().err


def test_changer_le_mot_de_passe_d_un_compte(reglages, monkeypatch):
    monkeypatch.setenv("SONDE_MOT_DE_PASSE", BON)
    lancer(reglages, "creer-compte", "marie")
    monkeypatch.setenv("SONDE_MOT_DE_PASSE", "Letchi-Combava-1946")
    assert lancer(reglages, "mot-de-passe", "marie") == 0
    assert lancer(reglages, "mot-de-passe", "absent") == 2


def test_cycle_unique(reglages, echantillons, capsys):
    shutil.copy(echantillons / "eve_scenario.json", charger(reglages).dossier_journaux + "/eve-2026-05-28.json")
    assert lancer(reglages, "cycle") == 0
    assert "29 événements" in capsys.readouterr().out


def test_surveiller_un_nombre_de_cycles(reglages, capsys):
    assert lancer(reglages, "surveiller", "--cycles", "2", "--intervalle", "0") == 0


def test_etat(reglages, echantillons, capsys):
    assert lancer(reglages, "etat") == 1               # jamais alimentée : muette
    shutil.copy(echantillons / "eve_scenario.json", charger(reglages).dossier_journaux + "/eve-2026-05-28.json")
    lancer(reglages, "cycle")
    capsys.readouterr()
    assert lancer(reglages, "etat") == 0
    sortie = capsys.readouterr().out
    assert "5 appareils" in sortie and "incident" in sortie


def test_rapport_en_ligne_de_commande(reglages, echantillons, tmp_path):
    shutil.copy(echantillons / "eve_scenario.json", charger(reglages).dossier_journaux + "/eve-2026-05-28.json")
    lancer(reglages, "cycle")
    sortie = tmp_path / "r.pdf"
    assert lancer(reglages, "rapport", "--jours", "400", "--sortie", str(sortie)) == 0
    assert sortie.read_bytes()[:5] == b"%PDF-"


def test_effacer_les_donnees_demande_confirmation(reglages):
    lancer(reglages, "initialiser")
    donnees = charger(reglages).dossier_donnees
    assert lancer(reglages, "effacer-donnees") == 2
    assert os.listdir(donnees)
    assert lancer(reglages, "effacer-donnees", "--confirmer") == 0
    assert not os.path.exists(donnees) or os.listdir(donnees) == []


def test_effacer_les_donnees_supprime_aussi_les_journaux(reglages, echantillons):
    c = charger(reglages)
    shutil.copy(echantillons / "eve_scenario.json", c.dossier_journaux + "/eve-2026-05-28.json")
    lancer(reglages, "cycle")
    lancer(reglages, "effacer-donnees", "--confirmer")
    assert os.listdir(c.dossier_journaux) == []


def test_reglage_inconnu_signale(tmp_path, capsys):
    fichier = tmp_path / "sonde.toml"
    fichier.write_text('nom_cliant = "faute de frappe"\n')
    assert main(["--config", str(fichier), "verifier-config"]) == 2
    assert "nom_cliant" in capsys.readouterr().err


def test_fichier_de_reglages_absent(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "absent.toml"), "verifier-config"]) == 2
    assert "introuvable" in capsys.readouterr().err


def test_verifier_config_valide(reglages, capsys):
    assert lancer(reglages, "verifier-config") == 0
    assert "Cabinet Hoarau" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as sortie:
        main(["--version"])
    assert sortie.value.code == 0 and "0.1.0" in capsys.readouterr().out


def test_commande_installee():
    resultat = subprocess.run([".venv/bin/python", "-m", "sonde", "--version"], capture_output=True, text=True)
    assert resultat.returncode == 0 and "0.1.0" in resultat.stdout
