"""F11/F12 : inventaire des appareils du réseau."""
import pytest

from shadowreef.inventaire import Inventaire

from .conftest import T0


@pytest.fixture
def inv(base, config):
    return Inventaire(base, config)


def test_nouvelle_adresse_cree_un_appareil(inv):
    ident, nouveau = inv.voir("192.168.1.10", T0)
    assert nouveau is True
    a = inv.appareil(ident)
    assert a["adresses"] == ["192.168.1.10"]
    assert a["premiere_vue"] == T0 and a["derniere_vue"] == T0
    assert a["connu"] is False


def test_revoir_un_appareil_met_a_jour_sans_doublon(inv):
    ident, _ = inv.voir("192.168.1.10", T0)
    ident2, nouveau = inv.voir("192.168.1.10", T0 + 60)
    assert ident2 == ident and nouveau is False
    assert inv.appareil(ident)["derniere_vue"] == T0 + 60
    assert len(inv.lister()) == 1


def test_evenements_dans_le_desordre(inv):
    ident, _ = inv.voir("192.168.1.10", T0 + 100)
    inv.voir("192.168.1.10", T0)
    a = inv.appareil(ident)
    assert a["premiere_vue"] == T0 and a["derniere_vue"] == T0 + 100


def test_mac_apprise_apres_coup_se_rattache(inv):
    ident, _ = inv.voir("192.168.1.10", T0)
    ident2, nouveau = inv.voir("192.168.1.10", T0 + 1, mac="00:11:22:33:44:10")
    assert ident2 == ident and nouveau is False
    assert inv.appareil(ident)["mac"] == "00:11:22:33:44:10"


def test_changement_d_adresse_dhcp_garde_le_meme_appareil(inv):
    ident, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10")
    ident2, nouveau = inv.voir("192.168.1.57", T0 + 3600, mac="00:11:22:33:44:10")
    assert ident2 == ident and nouveau is False
    assert sorted(inv.appareil(ident)["adresses"]) == ["192.168.1.10", "192.168.1.57"]


def test_adresse_reattribuee_a_une_autre_machine(inv):
    a, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10")
    b, nouveau = inv.voir("192.168.1.10", T0 + 7200, mac="00:11:22:33:44:99")
    assert b != a and nouveau is True
    assert inv.appareil_de("192.168.1.10") == b
    assert inv.appareil(a)["adresses"] == []


def test_ipv4_et_ipv6_d_une_meme_machine(inv):
    a, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10")
    b, nouveau = inv.voir("fe80::1234", T0 + 1, mac="00:11:22:33:44:10")
    assert a == b and nouveau is False


def test_mac_en_majuscules_normalisee(inv):
    a, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:AA:BB:CC")
    b, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:aa:bb:cc")
    assert a == b and inv.appareil(a)["mac"] == "00:11:22:aa:bb:cc"


def test_mac_de_diffusion_ignoree(inv):
    a, _ = inv.voir("192.168.1.10", T0, mac="ff:ff:ff:ff:ff:ff")
    assert inv.appareil(a)["mac"] is None


def test_routeur_detecte_quand_trop_d_adresses_pour_une_mac(inv, config):
    config.passerelle_max_adresses = 3
    routeur = "aa:aa:aa:00:00:01"
    premier, _ = inv.voir("10.0.1.1", T0, mac=routeur)
    for i in range(2, 4):
        inv.voir(f"10.0.1.{i}", T0 + i, mac=routeur)
    assert inv.appareil(premier)["passerelle"] is False
    # 4e adresse derrière la même MAC : c'est un routeur, pas une machine
    autre, nouveau = inv.voir("10.0.1.4", T0 + 10, mac=routeur)
    assert autre != premier and nouveau is True
    assert inv.appareil(premier)["passerelle"] is True
    assert inv.appareil(autre)["mac"] is None
    # les suivantes aussi deviennent des appareils distincts
    encore, _ = inv.voir("10.0.1.5", T0 + 11, mac=routeur)
    assert encore not in (premier, autre)


def test_nom_reseau_appris_par_dhcp(inv):
    ident, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10", nom="PC-COMPTA")
    assert inv.appareil(ident)["nom_reseau"] == "PC-COMPTA"
    inv.voir("192.168.1.10", T0 + 1, mac="00:11:22:33:44:10")  # sans nom : on garde l'ancien
    assert inv.appareil(ident)["nom_reseau"] == "PC-COMPTA"


def test_nommer_et_marquer_connu(inv):
    ident, _ = inv.voir("192.168.1.10", T0)
    inv.nommer(ident, "  Poste de Marie  ")
    inv.marquer_connu(ident, True)
    a = inv.appareil(ident)
    assert a["etiquette"] == "Poste de Marie" and a["connu"] is True
    assert a["nom_affiche"] == "Poste de Marie"


def test_nom_affiche_par_defaut(inv):
    a, _ = inv.voir("192.168.1.10", T0, nom="PC-COMPTA")
    b, _ = inv.voir("192.168.1.11", T0)
    assert inv.appareil(a)["nom_affiche"] == "PC-COMPTA"
    assert inv.appareil(b)["nom_affiche"] == "192.168.1.11"


def test_etiquette_trop_longue_refusee(inv):
    ident, _ = inv.voir("192.168.1.10", T0)
    with pytest.raises(ValueError):
        inv.nommer(ident, "x" * 200)


def test_appareil_inconnu(inv):
    assert inv.appareil(999) is None
    assert inv.appareil_de("192.168.1.250") is None
    with pytest.raises(KeyError):
        inv.nommer(999, "x")


def test_fabricant_depuis_le_fichier(base, config, tmp_path):
    fichier = tmp_path / "manuf"
    fichier.write_text("# commentaire\n00:11:22\tCimsys\tCIMSYS Inc\nDE:AD:BE\tTestCo\n")
    config.fichier_fabricants = str(fichier)
    inv = Inventaire(base, config)
    a, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10")
    b, _ = inv.voir("192.168.1.11", T0, mac="12:34:56:00:00:01")
    assert inv.appareil(a)["fabricant"] == "CIMSYS Inc"
    assert inv.appareil(b)["fabricant"] == ""


def test_liste_triee_par_derniere_activite(inv):
    a, _ = inv.voir("192.168.1.10", T0)
    b, _ = inv.voir("192.168.1.11", T0 + 50)
    assert [x["id"] for x in inv.lister()] == [b, a]


def test_base_persistante(tmp_path, config):
    from shadowreef.stockage import Base

    chemin = tmp_path / "p.db"
    b1 = Base(chemin); b1.initialiser()
    ident, _ = Inventaire(b1, config).voir("192.168.1.10", T0, mac="00:11:22:33:44:10")
    b1.fermer()
    b2 = Base(chemin); b2.initialiser()  # initialiser deux fois ne casse rien
    assert Inventaire(b2, config).appareil(ident)["mac"] == "00:11:22:33:44:10"
    b2.fermer()
