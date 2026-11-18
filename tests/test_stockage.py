import pytest


def test_lot_valide_tout_ou_rien(base):
    with base.lot():
        base.ecrire_meta("a", "1")
        base.ecrire_meta("b", "2")
    assert base.lire_meta("a") == "1" and base.lire_meta("b") == "2"
    with pytest.raises(RuntimeError):
        with base.lot():
            base.ecrire_meta("a", "changé")
            raise RuntimeError("panne")
    assert base.lire_meta("a") == "1"   # l'écriture du lot raté est annulée


def test_lots_imbriques(base):
    with base.lot():
        base.ecrire_meta("a", "1")
        with base.lot():
            base.ecrire_meta("b", "2")
    assert base.lire_meta("b") == "2"


def test_meta_defaut_et_remplacement(base):
    assert base.lire_meta("absent") is None
    assert base.lire_meta("absent", "x") == "x"
    base.ecrire_meta("k", "1"); base.ecrire_meta("k", "2")
    assert base.lire_meta("k") == "2"


def test_fichier_reserve_au_proprietaire(base):
    assert (base.chemin.stat().st_mode & 0o077) == 0
