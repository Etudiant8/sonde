"""Chaîne complète : suivi des journaux, cycle de la sonde, santé (N9), conservation (N3)."""
import json
import os
import shutil

import pytest

from shadowreef.alertes import ELEVEE
from shadowreef.traitement import Sonde

from .conftest import T0

MO = 1_000_000


@pytest.fixture
def config(config, tmp_path):
    config.dossier_donnees = str(tmp_path / "donnees")
    config.dossier_journaux = str(tmp_path / "journaux")
    os.makedirs(config.dossier_journaux)
    config.journal_eve = str(tmp_path / "journaux" / "eve-*.json")
    return config


@pytest.fixture
def sonde(config):
    s = Sonde(config)
    yield s
    s.fermer()


def ligne_flux(src, dst, port, quand, etabli=True, envoyes=1000):
    from datetime import datetime, timezone

    date = datetime.fromtimestamp(quand, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    return json.dumps({"timestamp": date, "event_type": "flow", "src_ip": src, "src_port": 50000, "dest_ip": dst,
                       "dest_port": port, "proto": "TCP",
                       "flow": {"pkts_toserver": 3, "pkts_toclient": 3, "bytes_toserver": envoyes, "bytes_toclient": 500, "start": date},
                       "tcp": {"tcp_flags_tc": "12" if etabli else "14"}}) + "\n"


def journal_du_jour(config, nom="eve-2026-05-28.json"):
    return os.path.join(config.dossier_journaux, nom)


# ------------------------------------------------------- suivi des fichiers

def test_ne_lit_que_les_nouvelles_lignes(sonde, config):
    chemin = journal_du_jour(config)
    with open(chemin, "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0))
    assert sonde.cycle(T0 + 1)["evenements"] == 1
    assert sonde.cycle(T0 + 2)["evenements"] == 0
    with open(chemin, "a") as f:
        f.write(ligne_flux("192.168.1.11", "203.0.113.1", 443, T0 + 3))
    assert sonde.cycle(T0 + 4)["evenements"] == 1
    assert len(sonde.inventaire.lister()) == 2


def test_ligne_en_cours_d_ecriture_attendue(sonde, config):
    chemin = journal_du_jour(config)
    complete = ligne_flux("192.168.1.10", "203.0.113.1", 443, T0)
    with open(chemin, "w") as f:
        f.write(complete[:40])              # Suricata n'a pas fini d'écrire la ligne
    assert sonde.cycle(T0 + 1)["evenements"] == 0
    with open(chemin, "a") as f:
        f.write(complete[40:])
    assert sonde.cycle(T0 + 2)["evenements"] == 1


def test_position_conservee_apres_redemarrage(config):
    chemin = journal_du_jour(config)
    with open(chemin, "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0))
    s1 = Sonde(config); s1.cycle(T0 + 1); s1.fermer()
    s2 = Sonde(config)
    assert s2.cycle(T0 + 2)["evenements"] == 0     # pas de relecture après une coupure (N8)
    s2.fermer()


def test_fichier_du_lendemain_pris_en_compte(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0))
    sonde.cycle(T0 + 1)
    with open(journal_du_jour(config, "eve-2026-05-29.json"), "w") as f:
        f.write(ligne_flux("192.168.1.11", "203.0.113.1", 443, T0 + 86400))
    assert sonde.cycle(T0 + 86401)["evenements"] == 1


def test_fichier_vide_puis_reecrit(sonde, config):
    chemin = journal_du_jour(config)
    with open(chemin, "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0) * 3)
    sonde.cycle(T0 + 1)
    with open(chemin, "w") as f:            # fichier remis à zéro
        f.write(ligne_flux("192.168.1.12", "203.0.113.1", 443, T0 + 5))
    assert sonde.cycle(T0 + 6)["evenements"] == 1


def test_aucun_journal_ne_plante_pas(sonde):
    assert sonde.cycle(T0)["evenements"] == 0


def test_lignes_abimees_comptees_mais_ignorees(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        f.write("{abîmé\n" + ligne_flux("192.168.1.10", "203.0.113.1", 443, T0) + "\n\n")
    bilan = sonde.cycle(T0 + 1)
    assert bilan["evenements"] == 1 and bilan["lignes_ignorees"] == 1


def test_gros_fichier_traite_par_tranches(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        for i in range(2500):
            f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0 + i))
    assert sonde.cycle(T0 + 3000)["evenements"] == 2500


# ----------------------------------------------- scénario réel (Suricata)

def test_scenario_suricata_pendant_l_apprentissage(sonde, config, echantillons):
    shutil.copy(echantillons / "eve_scenario.json", journal_du_jour(config))
    sonde.cycle(T0 + 60)
    inv, journal = sonde.inventaire, sonde.journal

    compta = inv.appareil(inv.appareil_de("192.168.1.10"))
    assert compta["nom_reseau"] == "PC-COMPTA" and compta["mac"] == "00:11:22:33:44:10"
    # les 15 adresses balayées qui n'existent pas ne sont pas dans l'inventaire
    assert sorted(a["adresses"][0] for a in inv.lister()) == [
        "192.168.1.1", "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.66"]

    ouverts = {i["appareil_id"]: i for i in journal.incidents(etat="ouvert")}
    attaque = ouverts[inv.appareil_de("192.168.1.10")]
    assert attaque["gravite"] == ELEVEE and "attaque connue" in attaque["resume"]
    balayage = ouverts[inv.appareil_de("192.168.1.66")]
    assert "15 machines" in balayage["resume"] and "445" in balayage["resume"]
    assert len(ouverts) == 2                  # rien d'autre pendant l'apprentissage

    faiblesses = {(f["type"], f["detail"]["port"]) for f in journal.faiblesses()}
    assert faiblesses == {("non_chiffre", 23), ("service_expose", 3389)}
    assert journal.etat_general() == "rouge"


def test_scenario_suricata_apres_l_apprentissage(sonde, config, echantillons):
    config.apprentissage_heures = 0
    config.sortie_plancher_mo = 1
    shutil.copy(echantillons / "eve_scenario.json", journal_du_jour(config))
    sonde.cycle(T0 + 60)
    types = {a["type"] for i in sonde.journal.incidents() for a in sonde.journal.alertes_de(i["id"])}
    assert {"signature", "balayage", "sortie_volume", "nouvel_appareil"} <= types
    nas = sonde.inventaire.appareil_de("192.168.1.30")
    volume = [i for i in sonde.journal.incidents() if i["appareil_id"] == nas][0]
    assert "2,1 Mo" in volume["resume"]


def test_rejouer_le_meme_journal_ne_double_rien(sonde, config, echantillons):
    shutil.copy(echantillons / "eve_scenario.json", journal_du_jour(config))
    sonde.cycle(T0 + 60)
    avant = len(sonde.journal.incidents())
    shutil.copy(echantillons / "eve_scenario.json", journal_du_jour(config, "eve-2026-05-29.json"))
    sonde.cycle(T0 + 120)
    assert len(sonde.journal.incidents()) == avant


# ---------------------------------------------------------------- Zeek

def test_journaux_zeek(config, tmp_path):
    zeek = tmp_path / "zeek"; zeek.mkdir()
    config.dossier_zeek = str(zeek)
    (zeek / "dhcp.log").write_text(json.dumps({"ts": T0, "mac": "00:11:22:33:44:10", "host_name": "PC-COMPTA", "assigned_addr": "192.168.1.10"}) + "\n")
    (zeek / "conn.log").write_text("".join(
        json.dumps({"ts": T0 + i, "id.orig_h": "192.168.1.66", "id.orig_p": 5000 + i, "id.resp_h": f"192.168.1.{100 + i}",
                    "id.resp_p": 445, "proto": "tcp", "conn_state": "REJ"}) + "\n" for i in range(12)))
    s = Sonde(config)
    assert s.cycle(T0 + 60)["evenements"] == 13
    assert s.inventaire.appareil(s.inventaire.appareil_de("192.168.1.10"))["nom_reseau"] == "PC-COMPTA"
    assert "balayage" in {a["type"] for i in s.journal.incidents() for a in s.journal.alertes_de(i["id"])}
    s.fermer()


# ------------------------------------------------- santé de la sonde (N9)

def test_sonde_muette_signalee_puis_retablie(sonde, config):
    chemin = journal_du_jour(config)
    with open(chemin, "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0))
    sonde.cycle(T0)
    silence = config.silence_max_minutes * 60
    sonde.cycle(T0 + silence - 10)
    assert sonde.journal.etat_general() == "vert"
    sonde.cycle(T0 + silence + 10)
    muets = [i for i in sonde.journal.incidents(etat="ouvert") if i["appareil_id"] is None]
    assert len(muets) == 1 and muets[0]["gravite"] == ELEVEE and "plus aucun trafic" in muets[0]["resume"]
    sonde.cycle(T0 + silence + 600)           # toujours muette : pas de second incident
    assert len([i for i in sonde.journal.incidents() if i["appareil_id"] is None]) == 1
    with open(chemin, "a") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0 + silence + 700))
    sonde.cycle(T0 + silence + 700)           # le trafic revient : l'incident se ferme tout seul
    assert [i for i in sonde.journal.incidents(etat="ouvert") if i["appareil_id"] is None] == []


def test_sonde_jamais_alimentee_signalee(sonde, config):
    """Port miroir mal configuré : aucun trafic depuis l'installation."""
    sonde.cycle(T0)
    sonde.cycle(T0 + config.silence_max_minutes * 60 + 1)
    assert sonde.journal.etat_general() == "rouge"


def test_etat_de_sante(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 443, T0))
    sonde.cycle(T0 + 5)
    sante = sonde.sante(T0 + 65)
    assert sante["dernier_trafic_il_y_a"] == 60 and sante["muette"] is False
    assert sante["apprentissage"] is True and sante["appareils"] == 1


def test_signal_de_vie_optionnel(config):
    appels = []
    config.url_signal_de_vie = "https://exemple.invalid/ping/abc"
    s = Sonde(config, ouvrir_url=lambda url, delai: appels.append(url))
    s.cycle(T0)
    assert appels == ["https://exemple.invalid/ping/abc"]
    s.fermer()


def test_signal_de_vie_desactive_par_defaut_et_panne_toleree(config):
    def en_panne(url, delai):
        raise OSError("pas de réseau")

    s = Sonde(config, ouvrir_url=en_panne)
    s.cycle(T0)                                   # url vide : aucun appel
    config.url_signal_de_vie = "https://exemple.invalid/ping"
    s.cycle(T0 + 1)                               # panne : la sonde continue
    s.fermer()


# ------------------------------------------------------ conservation (N3)

def test_purge_des_donnees_anciennes(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        f.write(ligne_flux("192.168.1.10", "203.0.113.1", 4444, T0, envoyes=10 * MO))
        f.write(json.dumps({"timestamp": "2026-05-28T20:26:40.000000+0000", "event_type": "alert", "src_ip": "192.168.1.10",
                            "dest_ip": "203.0.113.1", "proto": "TCP", "alert": {"signature": "x", "signature_id": 1, "severity": 2}}) + "\n")
    sonde.cycle(T0)
    incident = sonde.journal.incidents()[0]["id"]
    sonde.journal.resoudre(incident, T0 + 10)
    tard = T0 + (config.conservation_jours + 1) * 86400
    sonde.cycle(tard)
    assert sonde.journal.incident(incident) is None
    assert sonde.base.un("SELECT COUNT(*) n FROM sortie_jour")["n"] == 0
    assert sonde.base.un("SELECT COUNT(*) n FROM alertes")["n"] == 1      # il reste l'alerte « sonde muette »
    assert len(sonde.inventaire.lister()) == 1                             # l'inventaire, lui, est conservé


def test_incident_ouvert_jamais_purge(sonde, config):
    with open(journal_du_jour(config), "w") as f:
        f.write(json.dumps({"timestamp": "2026-05-28T20:26:40.000000+0000", "event_type": "alert", "src_ip": "192.168.1.10",
                            "dest_ip": "203.0.113.1", "proto": "TCP", "alert": {"signature": "x", "signature_id": 1, "severity": 2}}) + "\n")
    sonde.cycle(T0)
    sonde.cycle(T0 + (config.conservation_jours + 5) * 86400)
    assert any(i["appareil_id"] is not None for i in sonde.journal.incidents(etat="ouvert"))


def test_vieux_journaux_supprimes_quand_le_disque_est_plein(sonde, config):
    config.journaux_max_go = 3000 / 1e9                     # plafond minuscule pour le test : 3 000 octets
    for i, nom in enumerate(["eve-2026-05-26.json", "eve-2026-05-27.json", "eve-2026-05-28.json"]):
        chemin = journal_du_jour(config, nom)
        with open(chemin, "w") as f:
            f.write("x" * 1400 + "\n")
        os.utime(chemin, (T0 + i * 86400, T0 + i * 86400))
    sonde.cycle(T0 + 3 * 86400)
    restants = sorted(os.listdir(config.dossier_journaux))
    assert restants == ["eve-2026-05-27.json", "eve-2026-05-28.json"]


def test_journal_en_cours_jamais_supprime(sonde, config):
    config.journaux_max_go = 10 / 1e9
    with open(journal_du_jour(config), "w") as f:
        f.write("x" * 5000 + "\n")
    sonde.cycle(T0)
    assert os.listdir(config.dossier_journaux) == ["eve-2026-05-28.json"]
