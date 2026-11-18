"""F1/F3 : lecture des journaux Suricata (eve.json) et Zeek (JSON)."""
import json

from sonde.lecture import lire_ligne_eve, lire_ligne_zeek

from .conftest import T0


def eve(echantillons):
    lignes = (echantillons / "eve_scenario.json").read_text().splitlines()
    return [e for e in (lire_ligne_eve(l) for l in lignes) if e is not None]


def test_flux_etabli_avec_volumes_et_mac(echantillons):
    flux = [e for e in eve(echantillons) if e.type == "flux" and e.port_dst == 443 and e.ip_src == "192.168.1.30"]
    assert len(flux) == 1
    f = flux[0]
    assert f.ip_dst == "203.0.113.99"
    assert f.proto == "TCP"
    assert f.octets_envoyes == 2077436
    assert f.octets_recus == 77330
    assert f.etabli is True
    assert f.mac_src == "00:11:22:33:44:30"
    assert f.mac_dst == "aa:aa:aa:00:00:01"


def test_flux_date_du_debut_de_connexion_et_non_de_l_ecriture(echantillons):
    f = [e for e in eve(echantillons) if e.type == "flux" and e.ip_src == "192.168.1.30"][0]
    # le NAS envoie ses données environ 15 s après le début du scénario
    assert 14 < f.quand - T0 < 17


def test_flux_refuse_n_est_pas_etabli(echantillons):
    balayage = [e for e in eve(echantillons) if e.type == "flux" and e.ip_src == "192.168.1.66"]
    assert len(balayage) == 15
    assert all(e.etabli is False for e in balayage)
    assert {e.port_dst for e in balayage} == {445}


def test_alerte_de_signature(echantillons):
    alertes = [e for e in eve(echantillons) if e.type == "alerte"]
    assert len(alertes) == 1
    a = alertes[0]
    assert a.donnees["signature"] == "GPL ATTACK_RESPONSE id check returned root"
    assert a.donnees["sid"] == 2100498
    assert a.donnees["gravite_suricata"] == 1
    assert {a.ip_src, a.ip_dst} == {"203.0.113.66", "192.168.1.10"}


def test_mac_ignoree_hors_flux(echantillons):
    """Dans une réponse DNS, la MAC source est celle de l'émetteur du paquet,
    pas celle de src_ip : on ne doit pas l'associer à l'adresse."""
    dns = [e for e in eve(echantillons) if e.type == "dns"]
    assert dns and all(e.mac_src is None and e.mac_dst is None for e in dns)


def test_reponse_dns_donne_les_adresses(echantillons):
    reponses = [e for e in eve(echantillons) if e.type == "dns" and e.donnees.get("reponses")]
    assert reponses[0].donnees["reponses"] == [("www.example.re", "203.0.113.10")]


def test_dhcp_donne_nom_mac_et_adresse(echantillons):
    dhcp = [e for e in eve(echantillons) if e.type == "dhcp"]
    demande = [e for e in dhcp if e.donnees.get("nom")][0]
    assert demande.donnees["mac"] == "00:11:22:33:44:10"
    assert demande.donnees["nom"] == "PC-COMPTA"
    assert demande.donnees["ip"] == "192.168.1.10"
    accuse = [e for e in dhcp if not e.donnees.get("nom")][0]
    assert accuse.donnees["ip"] == "192.168.1.10"


def test_http_donne_le_nom_du_serveur(echantillons):
    http = [e for e in eve(echantillons) if e.type == "nom"]
    assert ("203.0.113.66", "mauvais.example") in [(e.ip_dst, e.donnees["nom"]) for e in http]


def test_tls_donne_le_nom_du_serveur():
    ligne = json.dumps({"timestamp": "2026-05-28T20:26:40.010000+0000", "event_type": "tls",
                        "src_ip": "192.168.1.10", "src_port": 1, "dest_ip": "203.0.113.5", "dest_port": 443,
                        "proto": "TCP", "tls": {"sni": "banque.example", "version": "TLS 1.3"}})
    e = lire_ligne_eve(ligne)
    assert e.type == "nom" and e.ip_dst == "203.0.113.5" and e.donnees["nom"] == "banque.example"


def test_lignes_invalides_ou_inutiles_ignorees():
    assert lire_ligne_eve("") is None
    assert lire_ligne_eve("{pas du json") is None
    assert lire_ligne_eve('{"event_type":"stats","timestamp":"2026-05-28T20:26:40.010000+0000"}') is None
    assert lire_ligne_eve('{"event_type":"flow"}') is None  # incomplet
    assert lire_ligne_eve('[1,2,3]') is None


def test_flux_udp_sans_reponse_non_etabli():
    ligne = json.dumps({"timestamp": "2026-05-28T20:26:40.010000+0000", "event_type": "flow",
                        "src_ip": "192.168.1.10", "src_port": 1, "dest_ip": "192.168.1.9", "dest_port": 161,
                        "proto": "UDP", "flow": {"pkts_toserver": 3, "pkts_toclient": 0, "bytes_toserver": 200,
                                                 "bytes_toclient": 0, "start": "2026-05-28T20:26:40.010000+0000"}})
    assert lire_ligne_eve(ligne).etabli is False


# --- Zeek -----------------------------------------------------------------

def test_zeek_conn():
    ligne = json.dumps({"ts": T0 + 1.5, "uid": "C1", "id.orig_h": "192.168.1.10", "id.orig_p": 5000,
                        "id.resp_h": "203.0.113.10", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                        "orig_bytes": 1200, "resp_bytes": 5400, "orig_ip_bytes": 1500, "resp_ip_bytes": 5800,
                        "conn_state": "SF", "orig_l2_addr": "00:11:22:33:44:10", "resp_l2_addr": "aa:aa:aa:00:00:01"})
    e = lire_ligne_zeek(ligne, "conn")
    assert (e.type, e.ip_src, e.ip_dst, e.port_dst, e.proto) == ("flux", "192.168.1.10", "203.0.113.10", 443, "TCP")
    assert e.quand == T0 + 1.5
    assert e.octets_envoyes == 1500 and e.octets_recus == 5800
    assert e.etabli is True and e.app == "ssl"
    assert e.mac_src == "00:11:22:33:44:10"


def test_zeek_conn_refusee():
    ligne = json.dumps({"ts": T0, "id.orig_h": "192.168.1.66", "id.orig_p": 1, "id.resp_h": "192.168.1.5",
                        "id.resp_p": 445, "proto": "tcp", "conn_state": "REJ"})
    e = lire_ligne_zeek(ligne, "conn")
    assert e.etabli is False and e.octets_envoyes == 0


def test_zeek_dns_et_dhcp():
    dns = lire_ligne_zeek(json.dumps({"ts": T0, "id.orig_h": "192.168.1.10", "id.orig_p": 1, "id.resp_h": "192.168.1.1",
                                      "id.resp_p": 53, "proto": "udp", "query": "www.example.re",
                                      "answers": ["cdn.example.re", "203.0.113.10"]}), "dns")
    assert dns.type == "dns" and dns.donnees["reponses"] == [("www.example.re", "203.0.113.10")]
    dhcp = lire_ligne_zeek(json.dumps({"ts": T0, "mac": "00:11:22:33:44:10", "host_name": "PC-COMPTA",
                                       "assigned_addr": "192.168.1.10"}), "dhcp")
    assert dhcp.type == "dhcp" and dhcp.donnees == {"mac": "00:11:22:33:44:10", "nom": "PC-COMPTA", "ip": "192.168.1.10"}


def test_zeek_ligne_invalide():
    assert lire_ligne_zeek("#fields ts uid", "conn") is None
    assert lire_ligne_zeek("{}", "conn") is None
    assert lire_ligne_zeek("{}", "inconnu") is None
