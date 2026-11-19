"""Fichiers de déploiement : réglages d'exemple, vérification de signature (N7), scripts."""
import os
import re
import subprocess
from dataclasses import fields
from pathlib import Path

import pytest

from shadowreef.config import Config, charger

RACINE = Path(__file__).parent.parent
EXEMPLE = RACINE / "deploiement" / "shadowreef.exemple.toml"
VERIFIER = RACINE / "scripts" / "verifier_version.sh"


def test_reglages_d_exemple_valides():
    config = charger(EXEMPLE)
    assert config.nom_client and config.fuseau == "Indian/Reunion"


def test_tous_les_reglages_sont_documentes():
    """Chaque réglage du programme apparaît (actif ou en commentaire) dans le fichier d'exemple."""
    texte = EXEMPLE.read_text()
    manquants = [c.name for c in fields(Config) if not re.search(rf"^#?\s*{c.name}\s*=", texte, re.M)]
    assert manquants == []


def test_exemple_sans_secret():
    texte = EXEMPLE.read_text()
    assert not re.search(r'^smtp_mot_de_passe\s*=\s*"[^"]+"', texte, re.M)


@pytest.fixture
def cles(tmp_path):
    privee, publique = tmp_path / "privee.pem", tmp_path / "publique.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(privee)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(privee), "-pubout", "-out", str(publique)], check=True, capture_output=True)
    return privee, publique


def signer(privee, archive):
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(privee), "-rawin", "-in", str(archive),
                    "-out", str(archive) + ".sig"], check=True, capture_output=True)


def verifier(publique, archive):
    return subprocess.run(["sh", str(VERIFIER), str(publique), str(archive)], capture_output=True, text=True)


def test_version_signee_acceptee(tmp_path, cles):
    privee, publique = cles
    archive = tmp_path / "sonde-0.2.0.tar.gz"; archive.write_bytes(os.urandom(4096))
    signer(privee, archive)
    resultat = verifier(publique, archive)
    assert resultat.returncode == 0, resultat.stderr


def test_version_modifiee_refusee(tmp_path, cles):
    privee, publique = cles
    archive = tmp_path / "sonde-0.2.0.tar.gz"; archive.write_bytes(os.urandom(4096))
    signer(privee, archive)
    with open(archive, "ab") as f:
        f.write(b"code ajoute par un tiers")
    resultat = verifier(publique, archive)
    assert resultat.returncode != 0 and "REFUS" in resultat.stderr


def test_version_sans_signature_refusee(tmp_path, cles):
    _, publique = cles
    archive = tmp_path / "sonde-0.2.0.tar.gz"; archive.write_bytes(b"x")
    assert verifier(publique, archive).returncode != 0


def test_signature_d_une_autre_cle_refusee(tmp_path, cles):
    _, publique = cles
    autre = tmp_path / "autre.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(autre)], check=True, capture_output=True)
    archive = tmp_path / "sonde-0.2.0.tar.gz"; archive.write_bytes(os.urandom(4096))
    signer(autre, archive)
    assert verifier(publique, archive).returncode != 0


def test_arguments_manquants(tmp_path):
    assert subprocess.run(["sh", str(VERIFIER)], capture_output=True).returncode != 0


@pytest.mark.parametrize("script", ["installer.sh", "desinstaller.sh", "mettre_a_jour.sh", "verifier_version.sh", "ecrire_reglages.sh"])
def test_scripts_syntaxe_valide(script):
    chemin = RACINE / "scripts" / script
    assert chemin.is_file()
    assert subprocess.run(["sh", "-n", str(chemin)], capture_output=True).returncode == 0
    assert chemin.read_text().startswith("#!/bin/sh")


def test_compose_valide():
    resultat = subprocess.run(["docker", "compose", "-f", str(RACINE / "deploiement" / "docker-compose.yml"), "config", "-q"],
                              capture_output=True, text=True,
                              env={**os.environ, "SHADOWREEF_INTERFACE": "eth1"})
    assert resultat.returncode == 0, resultat.stderr


@pytest.mark.parametrize("nom", ['Cabinet "Hoarau" & Fils', "L'Atelier du Sud | 974", "Société \\ Réunion", "Garage $HOME `id`", "Simple"])
def test_nom_du_client_ecrit_sans_casser_les_reglages(tmp_path, nom):
    """Le nom saisi à l'installation peut contenir n'importe quel caractère."""
    destination = tmp_path / "shadowreef.toml"
    resultat = subprocess.run(["sh", str(RACINE / "scripts" / "ecrire_reglages.sh"), nom, str(EXEMPLE), str(destination)],
                              capture_output=True, text=True)
    assert resultat.returncode == 0, resultat.stderr
    assert charger(destination).nom_client == nom
    assert destination.read_text().count("nom_client =") == 1


@pytest.mark.skipif(os.geteuid() != 0, reason="le script exige les droits d'administrateur")
def test_desinstallation_refuse_un_dossier_qui_n_est_pas_celui_de_la_sonde(tmp_path):
    """Garde-fou : une erreur de réglage ne doit jamais faire supprimer autre chose que la sonde."""
    (tmp_path / "important.txt").write_text("à garder")
    resultat = subprocess.run(["sh", str(RACINE / "scripts" / "desinstaller.sh"), "--oui"], capture_output=True, text=True,
                              env={**os.environ, "SHADOWREEF_REGLAGES": str(tmp_path)})
    assert resultat.returncode != 0 and "Rien n'a été supprimé" in resultat.stderr
    assert (tmp_path / "important.txt").read_text() == "à garder"


@pytest.mark.skipif(os.geteuid() != 0, reason="le script exige les droits d'administrateur")
@pytest.mark.parametrize("dossier", ["/", "/etc", "/home"])
def test_desinstallation_refuse_les_dossiers_du_systeme(dossier):
    resultat = subprocess.run(["sh", str(RACINE / "scripts" / "desinstaller.sh"), "--oui"], capture_output=True, text=True,
                              env={**os.environ, "SHADOWREEF_REGLAGES": dossier})
    assert resultat.returncode != 0 and "refusé" in resultat.stderr


def test_les_scripts_n_appellent_que_des_services_existants():
    """Chaque « compose run » ou « compose exec » des scripts vise un service défini dans le fichier Compose."""
    resultat = subprocess.run(["docker", "compose", "-f", str(RACINE / "deploiement" / "docker-compose.yml"), "config", "--services"],
                              capture_output=True, text=True, env={**os.environ, "SHADOWREEF_INTERFACE": "eth1"})
    assert resultat.returncode == 0, resultat.stderr
    services = set(resultat.stdout.split())
    assert services == {"suricata", "analyse", "web"}
    appels = []
    for script in (RACINE / "scripts").glob("*.sh"):
        for ligne in script.read_text().splitlines():
            trouve = re.search(r'\$compose (?:run (?:--\S+ )*(?:-e \S+ )*|exec )(\w+)', ligne)
            if trouve:
                appels.append((script.name, trouve.group(1)))
    assert appels, "aucun appel trouvé : le test ne vérifie plus rien"
    assert [a for a in appels if a[1] not in services] == []
