"""F19 : comptes de l'interface (mot de passe fort, hachage, verrouillage)."""
import pytest

from sonde.comptes import MotDePasseRefuse, changer_mot_de_passe, creer_utilisateur, verifier

from .conftest import T0

BON = "Tamarin-Vanille-2026"


def test_creation_et_connexion(base, config):
    creer_utilisateur(base, "marie", BON)
    assert verifier(base, config, "marie", BON, T0) is True
    assert verifier(base, config, "marie", "mauvais-mot-de-passe", T0) is False
    assert verifier(base, config, "inconnu", BON, T0) is False


def test_mot_de_passe_jamais_stocke_en_clair(base):
    creer_utilisateur(base, "marie", BON)
    hachage = base.un("SELECT hachage FROM utilisateurs")["hachage"]
    assert BON not in hachage and hachage.startswith("scrypt$")


def test_deux_comptes_meme_mot_de_passe_hachages_differents(base):
    creer_utilisateur(base, "marie", BON)
    creer_utilisateur(base, "paul", BON)
    h = [l["hachage"] for l in base.tous("SELECT hachage FROM utilisateurs")]
    assert h[0] != h[1]


@pytest.mark.parametrize("faible", ["court", "12345678901234", "motdepasse123", "marie-marie-marie", "aaaaaaaaaaaaaaaa", ""])
def test_mots_de_passe_faibles_refuses(base, faible):
    with pytest.raises(MotDePasseRefuse):
        creer_utilisateur(base, "marie", faible)


@pytest.mark.parametrize("identifiant", ["", "a", "avec espace", "x" * 60, "<script>"])
def test_identifiants_invalides_refuses(base, identifiant):
    with pytest.raises(ValueError):
        creer_utilisateur(base, identifiant, BON)


def test_identifiant_deja_pris(base):
    creer_utilisateur(base, "marie", BON)
    with pytest.raises(ValueError):
        creer_utilisateur(base, "marie", BON + "-autre")


def test_verrouillage_apres_trop_d_essais(base, config):
    creer_utilisateur(base, "marie", BON)
    for i in range(config.web_verrouillage_essais):
        assert verifier(base, config, "marie", "essai-rate", T0 + i) is False
    # compte verrouillé : même le bon mot de passe est refusé
    assert verifier(base, config, "marie", BON, T0 + 10) is False
    apres = T0 + 10 + config.web_verrouillage_minutes * 60 + 1
    assert verifier(base, config, "marie", BON, apres) is True


def test_connexion_reussie_remet_le_compteur_a_zero(base, config):
    creer_utilisateur(base, "marie", BON)
    for i in range(config.web_verrouillage_essais - 1):
        verifier(base, config, "marie", "essai-rate", T0 + i)
    assert verifier(base, config, "marie", BON, T0 + 10) is True
    for i in range(config.web_verrouillage_essais - 1):
        verifier(base, config, "marie", "essai-rate", T0 + 20 + i)
    assert verifier(base, config, "marie", BON, T0 + 40) is True


def test_changement_de_mot_de_passe(base, config):
    creer_utilisateur(base, "marie", BON)
    nouveau = "Letchi-Combava-1946"
    with pytest.raises(MotDePasseRefuse):
        changer_mot_de_passe(base, "marie", "court")
    changer_mot_de_passe(base, "marie", nouveau)
    assert verifier(base, config, "marie", nouveau, T0) is True
    assert verifier(base, config, "marie", BON, T0) is False
    with pytest.raises(KeyError):
        changer_mot_de_passe(base, "absent", nouveau)
