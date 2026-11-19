"""F4 à F10 : détecteurs. Chaque test rejoue des événements réseau fabriqués à la main."""
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from shadowreef.alertes import ELEVEE, FAIBLE, MOYENNE, Journal
from shadowreef.detection import Detecteurs
from shadowreef.inventaire import Inventaire
from shadowreef.lecture import Evenement

MO = 1_000_000
REUNION = ZoneInfo("Indian/Reunion")


def heure_locale(annee, mois, jour, heure, minute=0) -> float:
    return datetime(annee, mois, jour, heure, minute, tzinfo=REUNION).timestamp()


# Lundi 1er juin 2026, 10 h à La Réunion : en pleines heures ouvrées
LUNDI_10H = heure_locale(2026, 6, 1, 10)
JOUR = 86400


@pytest.fixture
def config(config):
    config.apprentissage_heures = 0      # la plupart des tests se placent après l'apprentissage
    return config


@pytest.fixture
def monde(base, config):
    inv = Inventaire(base, config)
    journal = Journal(base, config, inv)
    return Detecteurs(base, config, inv, journal), inv, journal


def flux(src, dst, port, quand=LUNDI_10H, envoyes=1000, recus=1000, etabli=True, mac=None, mac_dst=None, app=""):
    return Evenement(quand=quand, type="flux", ip_src=src, ip_dst=dst, port_src=50000, port_dst=port, proto="TCP",
                     octets_envoyes=envoyes, octets_recus=recus, etabli=etabli, mac_src=mac, mac_dst=mac_dst, app=app)


def types_ouverts(journal):
    return sorted(a["type"] for i in journal.incidents(etat="ouvert") for a in journal.alertes_de(i["id"]))


# ------------------------------------------------------------ inventaire

def test_un_flux_inscrit_la_source_interne(monde):
    det, inv, _ = monde
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443, mac="00:11:22:33:44:10"))
    appareils = inv.lister()
    assert len(appareils) == 1 and appareils[0]["mac"] == "00:11:22:33:44:10"


def test_cible_qui_ne_repond_pas_n_est_pas_un_appareil(monde):
    """Un balayage vers des adresses vides ne doit pas remplir l'inventaire de fantômes."""
    det, inv, _ = monde
    det.traiter(flux("192.168.1.66", "192.168.1.200", 445, etabli=False))
    assert [a["adresses"] for a in inv.lister()] == [["192.168.1.66"]]


def test_cible_qui_repond_est_inscrite(monde):
    det, inv, _ = monde
    det.traiter(flux("192.168.1.10", "192.168.1.20", 445, mac_dst="00:11:22:33:44:20"))
    assert len(inv.lister()) == 2


def test_adresses_externes_et_speciales_jamais_inscrites(monde):
    det, inv, _ = monde
    det.traiter(flux("0.0.0.0", "255.255.255.255", 67))
    det.traiter(flux("203.0.113.5", "198.51.100.1", 443))
    assert inv.lister() == []


def test_dhcp_apporte_le_nom(monde):
    det, inv, _ = monde
    det.traiter(Evenement(quand=LUNDI_10H, type="dhcp", donnees={"mac": "00:11:22:33:44:10", "nom": "PC-COMPTA", "ip": "192.168.1.10"}))
    assert inv.lister()[0]["nom_reseau"] == "PC-COMPTA"


# ------------------------------------------------------ F5 nouvel appareil

def test_nouvel_appareil_signale_apres_l_apprentissage(monde):
    det, _, journal = monde
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443))
    assert types_ouverts(journal) == ["nouvel_appareil"]
    assert journal.incidents()[0]["gravite"] == MOYENNE


def test_nouvel_appareil_silencieux_pendant_l_apprentissage(monde, config):
    det, inv, journal = monde
    config.apprentissage_heures = 168
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443))
    det.traiter(flux("192.168.1.11", "203.0.113.10", 443, quand=LUNDI_10H + 167 * 3600))
    assert journal.incidents() == [] and len(inv.lister()) == 2
    det.traiter(flux("192.168.1.12", "203.0.113.10", 443, quand=LUNDI_10H + 169 * 3600))
    assert types_ouverts(journal) == ["nouvel_appareil"]


def test_appareil_deja_vu_non_resignale(monde):
    det, _, journal = monde
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443))
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443, quand=LUNDI_10H + 3 * JOUR))
    assert len(journal.incidents()) == 1


# ------------------------------------------------------------ F4 signature

def alerte(src, dst, gravite=1, sid=2100498, quand=LUNDI_10H):
    return Evenement(quand=quand, type="alerte", ip_src=src, ip_dst=dst, port_src=80, port_dst=40003, proto="TCP",
                     donnees={"signature": "GPL ATTACK_RESPONSE id check returned root", "sid": sid,
                              "categorie": "Potentially Bad Traffic", "gravite_suricata": gravite})


@pytest.fixture
def monde_peuple(monde):
    """Réseau déjà connu : les appareils existent, aucun incident ouvert."""
    det, inv, journal = monde
    for ip in ("192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.66"):
        ident, _ = inv.voir(ip, LUNDI_10H - 30 * JOUR)
    return det, inv, journal


def test_signature_rattachee_a_la_machine_interne(monde_peuple):
    det, inv, journal = monde_peuple
    det.traiter(alerte("203.0.113.66", "192.168.1.10"))
    i = journal.incidents()[0]
    assert i["appareil_id"] == inv.appareil_de("192.168.1.10") and i["gravite"] == ELEVEE
    a = journal.alertes_de(i["id"])[0]
    assert a["type"] == "signature" and a["cle"] == "2100498" and a["detail"]["tiers"] == "203.0.113.66"


@pytest.mark.parametrize("suricata, attendue", [(1, ELEVEE), (2, MOYENNE), (3, FAIBLE), (4, FAIBLE)])
def test_gravite_des_signatures(monde_peuple, suricata, attendue):
    det, _, journal = monde_peuple
    det.traiter(alerte("192.168.1.10", "203.0.113.66", gravite=suricata))
    assert journal.incidents()[0]["gravite"] == attendue


def test_signature_entre_deux_machines_internes_rattachee_a_la_source(monde_peuple):
    det, inv, journal = monde_peuple
    det.traiter(alerte("192.168.1.66", "192.168.1.20"))
    assert journal.incidents()[0]["appareil_id"] == inv.appareil_de("192.168.1.66")


# ------------------------------------------------------------- F7 balayage

def test_balayage_de_machines_sur_un_port(monde_peuple, config):
    det, inv, journal = monde_peuple
    for i in range(config.balayage_machines - 1):
        det.traiter(flux("192.168.1.66", f"192.168.1.{100 + i}", 445, quand=LUNDI_10H + i, etabli=False))
    assert journal.incidents() == []          # sous le seuil
    det.traiter(flux("192.168.1.66", "192.168.1.199", 445, quand=LUNDI_10H + 20, etabli=False))
    i = journal.incidents()[0]
    assert i["appareil_id"] == inv.appareil_de("192.168.1.66")
    a = journal.alertes_de(i["id"])[0]
    assert a["type"] == "balayage" and a["detail"]["port"] == 445 and a["detail"]["machines"] == config.balayage_machines


def test_balayage_lent_non_signale(monde_peuple, config):
    det, _, journal = monde_peuple
    for i in range(config.balayage_machines + 5):
        det.traiter(flux("192.168.1.66", f"192.168.1.{100 + i}", 445,
                         quand=LUNDI_10H + i * (config.balayage_fenetre_secondes + 1), etabli=False))
    assert journal.incidents() == []


def test_connexions_reussies_ne_sont_pas_un_balayage(monde_peuple, config):
    """Un serveur de supervision parle à beaucoup de machines : ce n'est pas une recherche de cibles."""
    det, _, journal = monde_peuple
    for i in range(config.balayage_machines + 5):
        det.traiter(flux("192.168.1.20", f"192.168.1.{100 + i}", 445, quand=LUNDI_10H + i, etabli=True))
    assert "balayage" not in types_ouverts(journal)


def test_balayage_de_ports_sur_une_machine(monde_peuple, config):
    det, _, journal = monde_peuple
    for port in range(1, config.balayage_ports + 1):
        det.traiter(flux("192.168.1.66", "192.168.1.20", port, quand=LUNDI_10H + port * 0.1, etabli=False))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["type"] == "balayage" and a["detail"]["cible"] == "192.168.1.20" and a["detail"]["ports"] == config.balayage_ports


def test_balayage_repete_reste_un_seul_incident(monde_peuple, config):
    det, _, journal = monde_peuple
    for i in range(60):
        det.traiter(flux("192.168.1.66", f"192.168.1.{100 + i}", 445, quand=LUNDI_10H + i, etabli=False))
    assert len(journal.incidents()) == 1
    assert journal.alertes_de(journal.incidents()[0]["id"])[0]["detail"]["machines"] == 60


# ------------------------------------------------------- F6 volume sortant

def test_gros_envoi_sans_historique(monde_peuple, config):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=config.sortie_plancher_mo * MO - 1))
    assert journal.incidents() == []
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=2 * MO, quand=LUNDI_10H + 60))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["type"] == "sortie_volume" and a["detail"]["octets"] > config.sortie_plancher_mo * MO


def test_volume_habituel_eleve_non_signale(monde_peuple, config):
    """Un NAS qui sauvegarde 2 Go chaque jour ne doit pas alerter tous les jours."""
    det, _, journal = monde_peuple
    config.apprentissage_heures = 96
    config.jours_ouvres = [0, 1, 2, 3, 4, 5, 6]   # le scénario déborde sur le week-end : on isole le volume
    debut = LUNDI_10H
    for j in range(4):       # quatre jours d'apprentissage à 2 Go
        det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=2000 * MO, quand=debut + j * JOUR))
    assert journal.incidents() == []
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=2500 * MO, quand=debut + 5 * JOUR))
    assert journal.incidents() == []          # 2,5 Go < 3 x 2 Go
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=7000 * MO, quand=debut + 6 * JOUR))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["type"] == "sortie_volume" and a["detail"]["habituel"] == 2000 * MO


def test_volume_interne_non_compte(monde_peuple, config):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "192.168.1.30", 445, envoyes=5000 * MO))
    assert "sortie_volume" not in types_ouverts(journal)


def test_volume_recu_non_compte(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443, envoyes=1000, recus=9000 * MO))
    assert journal.incidents() == []


def test_volume_compte_par_jour_local(monde_peuple, config):
    """23 h et 1 h du matin à La Réunion sont deux jours différents, même si c'est le même jour en UTC."""
    det, _, journal = monde_peuple
    moitie = config.sortie_plancher_mo * MO * 6 // 10
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=moitie, quand=heure_locale(2026, 6, 1, 23)))
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=moitie, quand=heure_locale(2026, 6, 2, 1)))
    assert "sortie_volume" not in types_ouverts(journal)


def test_destination_nommee_dans_l_alerte_de_volume(monde_peuple, config):
    det, _, journal = monde_peuple
    det.traiter(Evenement(quand=LUNDI_10H, type="dns", donnees={"question": "partage.example", "reponses": [("partage.example", "203.0.113.99")]}))
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=900 * MO))
    assert "partage.example" in journal.incidents()[0]["resume"]


# ---------------------------------------------------------- F9 hors heures

DIMANCHE_3H = heure_locale(2026, 6, 7, 3)


def test_envoi_nocturne_inhabituel(monde_peuple, config):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.50", 443, envoyes=config.hors_heures_plancher_mo * MO + 1, quand=DIMANCHE_3H))
    assert types_ouverts(journal) == ["hors_heures"]
    assert journal.incidents()[0]["gravite"] == FAIBLE


def test_meme_envoi_en_journee_non_signale(monde_peuple, config):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.50", 443, envoyes=config.hors_heures_plancher_mo * MO + 1, quand=LUNDI_10H))
    assert journal.incidents() == []


def test_petit_trafic_nocturne_ignore(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.50", 443, envoyes=2 * MO, quand=DIMANCHE_3H))
    assert journal.incidents() == []


def test_appareil_habituellement_actif_la_nuit(monde_peuple, config):
    det, _, journal = monde_peuple
    config.apprentissage_heures = 72
    nuit = heure_locale(2026, 6, 1, 2)
    for j in range(3):      # trois nuits de sauvegarde pendant l'apprentissage
        det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=200 * MO, quand=nuit + j * JOUR))
    det.traiter(flux("192.168.1.30", "203.0.113.99", 443, envoyes=200 * MO, quand=nuit + 5 * JOUR))
    assert "hors_heures" not in types_ouverts(journal)


def test_limites_des_heures_ouvrees(monde_peuple, config):
    det, _, journal = monde_peuple
    gros = config.hors_heures_plancher_mo * MO + 1
    det.traiter(flux("192.168.1.10", "203.0.113.50", 443, envoyes=gros, quand=heure_locale(2026, 6, 1, 7)))     # 7 h pile : ouvré
    det.traiter(flux("192.168.1.20", "203.0.113.50", 443, envoyes=gros, quand=heure_locale(2026, 6, 1, 18, 59)))  # avant 19 h : ouvré
    assert journal.incidents() == []
    det.traiter(flux("192.168.1.30", "203.0.113.50", 443, envoyes=gros, quand=heure_locale(2026, 6, 1, 19)))    # 19 h pile : fermé
    assert types_ouverts(journal) == ["hors_heures"]


# -------------------------------------------- F8 destinations inhabituelles

def test_connexion_directe_a_une_ip_jamais_vue_sur_port_inhabituel(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.77", 4444))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["type"] == "destination_inhabituelle" and a["detail"] == {"ip": "203.0.113.77", "port": 4444}


def test_destination_avec_nom_dns_non_signalee(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(Evenement(quand=LUNDI_10H, type="dns", donnees={"question": "jeu.example", "reponses": [("jeu.example", "203.0.113.77")]}))
    det.traiter(flux("192.168.1.10", "203.0.113.77", 4444))
    assert journal.incidents() == []


def test_destination_avec_nom_tls_non_signalee(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(Evenement(quand=LUNDI_10H, type="nom", ip_dst="203.0.113.77", donnees={"nom": "visio.example"}))
    det.traiter(flux("192.168.1.10", "203.0.113.77", 4444))
    assert journal.incidents() == []


def test_port_habituel_non_signale(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.77", 443))
    assert journal.incidents() == []


def test_destination_deja_connue_du_reseau_non_signalee(monde_peuple, config):
    det, _, journal = monde_peuple
    config.apprentissage_heures = 24
    det.traiter(flux("192.168.1.20", "203.0.113.77", 4444, quand=LUNDI_10H))             # vue pendant l'apprentissage
    det.traiter(flux("192.168.1.10", "203.0.113.77", 4444, quand=LUNDI_10H + 2 * JOUR))  # autre poste, plus tard
    assert journal.incidents() == []


def test_connexion_refusee_vers_l_exterieur_non_signalee(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.77", 4444, etabli=False))
    assert journal.incidents() == []


def test_nouveau_pays(base, config):
    inv = Inventaire(base, config)
    journal = Journal(base, config, inv)
    pays = {"203.0.113.10": "FR", "203.0.113.11": "FR", "198.51.100.9": "KP"}.get
    det = Detecteurs(base, config, inv, journal, pays_de=pays)
    config.apprentissage_heures = 24
    inv.voir("192.168.1.10", LUNDI_10H)
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443, quand=LUNDI_10H))               # FR appris
    det.traiter(flux("192.168.1.10", "203.0.113.11", 443, quand=LUNDI_10H + 2 * JOUR))    # FR encore : rien
    assert journal.incidents() == []
    det.traiter(flux("192.168.1.10", "198.51.100.9", 443, quand=LUNDI_10H + 2 * JOUR))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["type"] == "nouveau_pays" and a["detail"]["pays"] == "KP"
    det.traiter(flux("192.168.1.10", "198.51.100.9", 443, quand=LUNDI_10H + 9 * JOUR))    # déjà vu : pas de second incident
    assert len(journal.incidents()) == 1


# ---------------------------------------------------- F10 points faibles

def test_service_expose_a_internet(monde_peuple):
    det, inv, journal = monde_peuple
    det.traiter(flux("198.51.100.7", "192.168.1.20", 3389, app="rdp"))
    f = journal.faiblesses()
    assert len(f) == 1 and f[0]["type"] == "service_expose" and f[0]["appareil_id"] == inv.appareil_de("192.168.1.20")
    assert f[0]["detail"]["port"] == 3389 and f[0]["detail"]["service"] == "rdp"
    assert journal.incidents() == []


def test_tentative_entrante_refusee_n_est_pas_une_exposition(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("198.51.100.7", "192.168.1.20", 3389, etabli=False))
    assert journal.faiblesses() == []


def test_protocole_non_chiffre_interne(monde_peuple):
    det, inv, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "192.168.1.20", 23))
    f = journal.faiblesses()
    assert [x["type"] for x in f] == ["non_chiffre"]
    assert f[0]["appareil_id"] == inv.appareil_de("192.168.1.20")     # c'est le serveur qu'il faut corriger
    assert f[0]["detail"]["protocole"] == "Telnet" and f[0]["gravite"] == FAIBLE


def test_protocole_non_chiffre_vers_internet_plus_grave(monde_peuple):
    det, inv, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "203.0.113.5", 21))
    f = [x for x in journal.faiblesses() if x["type"] == "non_chiffre"][0]
    assert f["appareil_id"] == inv.appareil_de("192.168.1.10") and f["gravite"] == MOYENNE


def test_protocole_chiffre_non_signale(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(flux("192.168.1.10", "192.168.1.20", 22))
    assert journal.faiblesses() == []


# -------------------------------------------------------------- entretien

def test_entretien_purge_les_flux_anciens(monde_peuple, base, config):
    det, _, _ = monde_peuple
    det.traiter(flux("192.168.1.66", "192.168.1.100", 445, quand=LUNDI_10H, etabli=False))
    det.entretien(LUNDI_10H + config.balayage_fenetre_secondes * 3)
    assert base.un("SELECT COUNT(*) n FROM flux_recents")["n"] == 0


def test_evenement_incoherent_n_arrete_pas_la_sonde(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(Evenement(quand=LUNDI_10H, type="flux", ip_src="pas-une-ip", ip_dst="", port_dst=0))
    det.traiter(Evenement(quand=LUNDI_10H, type="dhcp", donnees={"mac": "", "nom": "", "ip": ""}))
    det.traiter(Evenement(quand=LUNDI_10H, type="inconnu"))
    assert journal.incidents() == []


def test_balayage_detecte_meme_si_les_flux_arrivent_dans_le_desordre(monde_peuple, config):
    """Suricata écrit les connexions terminées dans un ordre quelconque."""
    det, _, journal = monde_peuple
    ordre = [7, 2, 14, 0, 9, 4, 11, 1, 13, 6, 3, 12, 5, 10, 8]
    for i in ordre:
        det.traiter(flux("192.168.1.66", f"192.168.1.{100 + i}", 445, quand=LUNDI_10H + i, etabli=False))
    a = journal.alertes_de(journal.incidents()[0]["id"])[0]
    assert a["detail"]["machines"] == 15


def test_evenements_techniques_de_suricata_ignores(monde_peuple):
    """Les règles internes de Suricata (anomalies de décodage, n° 2200000 à 2299999) ne sont pas des attaques."""
    det, _, journal = monde_peuple
    e = alerte("192.168.1.30", "203.0.113.99", gravite=3, sid=2260002)
    e.donnees["signature"] = "SURICATA Applayer Protocol detection skipped"
    det.traiter(e)
    assert journal.incidents() == []


def test_fenetre_glissante_ecarte_les_connexions_trop_anciennes():
    from shadowreef.detection import _max_distincts

    lignes = [{"quand": t, "v": v} for t, v in [(0, "a"), (100, "b"), (200, "c"), (350, "d"), (360, "a"), (700, "e")]]
    assert _max_distincts(lignes, 300) == 4        # b, c, d, a entre 100 et 360
    assert _max_distincts(lignes, 50) == 2
    assert _max_distincts([], 300) == 0
    assert _max_distincts([{"quand": 0, "v": "a"}, {"quand": 1, "v": "a"}], 300) == 1


def test_balayage_etale_sur_deux_fenetres_non_signale(monde_peuple, config):
    """14 machines en 10 minutes, mais jamais 10 dans une même fenêtre de 5 minutes : pas d'alerte."""
    det, _, journal = monde_peuple
    instants = [i * 30 for i in range(9)] + [330 + i * 60 for i in range(5)]     # 9 en 4 min, puis 5 étalées
    for n, t in enumerate(instants):
        det.traiter(flux("192.168.1.66", f"192.168.1.{100 + n}", 445, quand=LUNDI_10H + t, etabli=False))
    assert journal.incidents() == []


def test_panne_interne_sur_un_evenement_n_arrete_pas_la_surveillance(monde_peuple, monkeypatch):
    det, inv, journal = monde_peuple

    def en_panne(*a, **k):
        raise RuntimeError("disque plein")

    monkeypatch.setattr(inv, "voir", en_panne)
    det.traiter(flux("192.168.1.10", "203.0.113.10", 443))        # ne lève pas d'exception
    monkeypatch.undo()
    det.traiter(alerte("203.0.113.66", "192.168.1.10"))           # l'événement suivant est bien traité
    assert len(journal.incidents()) == 1


def test_signature_sans_machine_interne(monde_peuple):
    det, _, journal = monde_peuple
    det.traiter(alerte("203.0.113.66", "198.51.100.1"))
    i = journal.incidents()[0]
    assert i["appareil_id"] is None and "repérée sur le réseau" in i["resume"]
