"""F13-F16 : regroupement en incidents, gravité, explication, exceptions."""
import pytest

from shadowreef.alertes import ELEVEE, FAIBLE, MOYENNE, Journal
from shadowreef.inventaire import Inventaire

from .conftest import T0

H = 3600


@pytest.fixture
def inv(base, config):
    return Inventaire(base, config)


@pytest.fixture
def journal(base, config, inv):
    return Journal(base, config, inv)


@pytest.fixture
def pc(inv):
    ident, _ = inv.voir("192.168.1.10", T0, nom="PC-COMPTA")
    return ident


def signature(journal, pc, quand, sid=2100498, gravite=ELEVEE):
    return journal.signaler("signature", pc, str(sid), gravite, quand,
                            {"signature": "GPL ATTACK_RESPONSE id check returned root", "tiers": "203.0.113.66"})


def test_une_alerte_cree_un_incident(journal, pc):
    signature(journal, pc, T0)
    incidents = journal.incidents()
    assert len(incidents) == 1
    i = incidents[0]
    assert i["gravite"] == ELEVEE and i["etat"] == "ouvert" and i["appareil_id"] == pc
    assert len(journal.alertes_de(i["id"])) == 1


def test_alertes_proches_du_meme_appareil_regroupees(journal, pc):
    signature(journal, pc, T0)
    journal.signaler("balayage", pc, "445", MOYENNE, T0 + 600, {"port": 445, "machines": 15})
    incidents = journal.incidents()
    assert len(incidents) == 1
    assert len(journal.alertes_de(incidents[0]["id"])) == 2
    assert incidents[0]["maj_le"] == T0 + 600


def test_alertes_eloignees_dans_le_temps_separees(journal, pc, config):
    signature(journal, pc, T0)
    journal.signaler("balayage", pc, "445", MOYENNE, T0 + config.fenetre_incident_minutes * 60 + 1, {"port": 445, "machines": 15})
    assert len(journal.incidents()) == 2


def test_appareils_differents_incidents_differents(journal, pc, inv):
    autre, _ = inv.voir("192.168.1.11", T0)
    signature(journal, pc, T0)
    signature(journal, autre, T0)
    assert len(journal.incidents()) == 2


def test_alerte_repetee_compte_sans_doublon(journal, pc):
    a = signature(journal, pc, T0)
    b = signature(journal, pc, T0 + 300)
    assert a == b
    alertes = journal.alertes_de(journal.incidents()[0]["id"])
    assert len(alertes) == 1 and alertes[0]["nombre"] == 2 and alertes[0]["derniere_vue"] == T0 + 300


def test_gravite_du_plus_grave(journal, pc):
    journal.signaler("hors_heures", pc, "2026-05-28", FAIBLE, T0, {"octets": 80_000_000})
    assert journal.incidents()[0]["gravite"] == FAIBLE
    journal.signaler("signature", pc, "1", MOYENNE, T0 + 60, {"signature": "x"})
    # deux signaux de nature différente sur le même appareil : la gravité monte d'un cran
    assert journal.incidents()[0]["gravite"] == ELEVEE


def test_gravite_plafonnee(journal, pc):
    signature(journal, pc, T0)
    journal.signaler("balayage", pc, "445", MOYENNE, T0 + 1, {"port": 445, "machines": 15})
    assert journal.incidents()[0]["gravite"] == ELEVEE


def test_meme_type_repete_ne_fait_pas_monter(journal, pc):
    journal.signaler("signature", pc, "1", MOYENNE, T0, {"signature": "a"})
    journal.signaler("signature", pc, "2", MOYENNE, T0 + 1, {"signature": "b"})
    assert journal.incidents()[0]["gravite"] == MOYENNE


def test_explication_en_francais_avec_action(journal, pc):
    signature(journal, pc, T0)
    i = journal.incidents()[0]
    assert "PC-COMPTA" in i["resume"]
    assert i["resume"].endswith(".")
    assert i["action"] and i["action"][0].isupper()
    assert "{" not in i["resume"] + i["action"]


def test_explication_mise_a_jour_quand_l_incident_grossit(journal, pc):
    signature(journal, pc, T0)
    avant = journal.incidents()[0]["resume"]
    journal.signaler("balayage", pc, "445", MOYENNE, T0 + 1, {"port": 445, "machines": 15})
    apres = journal.incidents()[0]["resume"]
    assert apres != avant and "445" in apres


def test_marquer_normal_ferme_et_empeche_le_retour(journal, pc):
    signature(journal, pc, T0)
    incident = journal.incidents()[0]["id"]
    journal.marquer_normal(incident, "outil du prestataire")
    assert journal.incident(incident)["etat"] == "normal"
    assert signature(journal, pc, T0 + 10 * H) is None      # ne revient plus
    assert len(journal.incidents(etat="ouvert")) == 0
    # une autre signature sur le même poste reste signalée
    assert signature(journal, pc, T0 + 10 * H, sid=42) is not None


def test_exception_limitee_a_l_appareil(journal, pc, inv):
    signature(journal, pc, T0)
    journal.marquer_normal(journal.incidents()[0]["id"])
    autre, _ = inv.voir("192.168.1.11", T0)
    assert signature(journal, autre, T0 + H) is not None


def test_supprimer_une_exception_retablit_l_alerte(journal, pc):
    signature(journal, pc, T0)
    journal.marquer_normal(journal.incidents()[0]["id"])
    exceptions = journal.exceptions()
    assert len(exceptions) == 1 and exceptions[0]["type"] == "signature"
    journal.supprimer_exception(exceptions[0]["id"])
    assert signature(journal, pc, T0 + H) is not None


def test_resoudre_puis_recidive_ouvre_un_nouvel_incident(journal, pc):
    signature(journal, pc, T0)
    premier = journal.incidents()[0]["id"]
    journal.resoudre(premier)
    assert journal.incident(premier)["etat"] == "resolu"
    signature(journal, pc, T0 + 600)
    ouverts = journal.incidents(etat="ouvert")
    assert len(ouverts) == 1 and ouverts[0]["id"] != premier


def test_incident_deja_ferme_non_modifiable(journal, pc):
    signature(journal, pc, T0)
    ident = journal.incidents()[0]["id"]
    journal.resoudre(ident)
    with pytest.raises(ValueError):
        journal.marquer_normal(ident)
    with pytest.raises(KeyError):
        journal.resoudre(9999)


def test_faiblesse_hors_incidents_et_sans_doublon(journal, pc):
    journal.signaler("non_chiffre", pc, "23", FAIBLE, T0, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    journal.signaler("non_chiffre", pc, "23", FAIBLE, T0 + 40 * 24 * H, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    assert journal.incidents() == []
    faiblesses = journal.faiblesses()
    assert len(faiblesses) == 1 and faiblesses[0]["nombre"] == 2
    assert "Telnet" in faiblesses[0]["texte"]


def test_faiblesse_acceptee_ne_revient_pas(journal, pc):
    ident = journal.signaler("non_chiffre", pc, "23", FAIBLE, T0, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    journal.accepter_faiblesse(ident)
    assert journal.faiblesses() == []
    assert journal.signaler("non_chiffre", pc, "23", FAIBLE, T0 + H, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse") is None


def test_appareil_reconnu_ferme_l_incident_nouvel_appareil(journal, pc, inv):
    journal.signaler("nouvel_appareil", pc, "", MOYENNE, T0, {})
    inv.marquer_connu(pc, True)
    journal.appareil_reconnu(pc, T0 + 60)
    assert journal.incidents(etat="ouvert") == []


def test_appareil_reconnu_ne_ferme_pas_un_incident_plus_large(journal, pc):
    journal.signaler("nouvel_appareil", pc, "", MOYENNE, T0, {})
    journal.signaler("balayage", pc, "445", MOYENNE, T0 + 1, {"port": 445, "machines": 15})
    journal.appareil_reconnu(pc, T0 + 60)
    assert len(journal.incidents(etat="ouvert")) == 1


def test_alerte_sans_appareil(journal):
    journal.signaler("sonde_muette", None, "", ELEVEE, T0, {"minutes": 45})
    i = journal.incidents()[0]
    assert i["appareil_id"] is None and "45" in i["resume"]


def test_etat_general(journal, pc):
    assert journal.etat_general() == "vert"
    journal.signaler("hors_heures", pc, "j", FAIBLE, T0, {"octets": 80_000_000})
    assert journal.etat_general() == "vert"       # un signal faible seul n'inquiète pas le dirigeant
    journal.signaler("nouvel_appareil", pc, "", MOYENNE, T0 + 3 * H, {})
    assert journal.etat_general() == "orange"
    signature(journal, pc, T0 + 6 * H)
    assert journal.etat_general() == "rouge"
    for i in journal.incidents(etat="ouvert"):
        journal.resoudre(i["id"])
    assert journal.etat_general() == "vert"


def test_tri_des_incidents_gravite_puis_date(journal, pc, inv):
    autre, _ = inv.voir("192.168.1.11", T0)
    journal.signaler("nouvel_appareil", autre, "", MOYENNE, T0 + 100, {})
    signature(journal, pc, T0)
    assert [i["gravite"] for i in journal.incidents()] == [ELEVEE, MOYENNE]


def test_type_inconnu_refuse(journal, pc):
    with pytest.raises(ValueError):
        journal.signaler("nimportequoi", pc, "", FAIBLE, T0, {})
    with pytest.raises(ValueError):
        journal.signaler("signature", pc, "", 7, T0, {})


def test_nombre_de_repetitions_affiche_seulement_pour_les_signatures(journal, pc):
    journal.signaler("balayage", pc, "port:445", MOYENNE, T0, {"port": 445, "machines": 12})
    journal.signaler("balayage", pc, "port:445", MOYENNE, T0 + 1, {"port": 445, "machines": 15})
    assert "fois" not in journal.incidents()[0]["resume"]
    autre = journal.signaler("signature", pc, "9", MOYENNE, T0 + 2, {"signature": "x"})
    journal.signaler("signature", pc, "9", MOYENNE, T0 + 3, {"signature": "x"})
    assert "(2 fois)" in journal.incidents()[0]["resume"] and autre


def test_le_signal_le_plus_parlant_ouvre_l_explication(journal, pc):
    """À gravité égale, « nouvel appareil » passe après un signal qui dit ce que fait l'appareil."""
    journal.signaler("nouvel_appareil", pc, "", MOYENNE, T0, {})
    journal.signaler("balayage", pc, "port:445", MOYENNE, T0 + 5, {"port": 445, "machines": 15})
    i = journal.incidents()[0]
    assert i["resume"].startswith("PC-COMPTA (192.168.1.10) a tenté de joindre 15 machines")
    assert "nouvel appareil" in i["resume"]
    assert i["action"].startswith("Vérifiez qui utilise cet appareil")


def test_phrase_de_signature_sans_parentheses_doublees(journal, pc):
    signature(journal, pc, T0)
    resume = journal.incidents()[0]["resume"]
    assert ") (" not in resume and "lors d'un échange avec 203.0.113.66" in resume


def test_signature_faible_formulee_sans_alarmer(journal, pc):
    """Une règle de faible importance ne doit ni parler d'attaque ni conseiller de débrancher."""
    journal.signaler("signature", pc, "7", FAIBLE, T0, {"signature": "ET INFO Session Traversal Utilities for NAT", "tiers": "203.0.113.5"})
    i = journal.incidents()[0]
    assert "attaque" not in i["resume"] and "ET INFO Session Traversal" in i["resume"]
    assert "Débranchez" not in i["action"] and "Aucune action" in i["action"]


def test_signature_moyenne_conseil_de_verification(journal, pc):
    journal.signaler("signature", pc, "8", MOYENNE, T0, {"signature": "ET POLICY curl User-Agent", "tiers": "203.0.113.5"})
    i = journal.incidents()[0]
    assert "Débranchez" not in i["action"] and "vérifier" in i["action"].lower()
    assert "activité suspecte" in i["resume"]
