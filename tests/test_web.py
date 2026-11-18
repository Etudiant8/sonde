"""F12, F16, F17, F18, F19, N5, N13 : interface web locale."""
import re

import pytest

from sonde.alertes import ELEVEE, FAIBLE, MOYENNE
from sonde.comptes import creer_utilisateur
from sonde.traitement import Sonde
from sonde.web import creer_application

from .conftest import T0

BON = "Tamarin-Vanille-2026"
HTTPS = "https://sonde.local"


class Horloge:
    def __init__(self):
        self.t = T0 + 3600

    def __call__(self):
        return self.t


@pytest.fixture
def config(config, tmp_path):
    config.dossier_donnees = str(tmp_path / "donnees")
    config.journal_eve = str(tmp_path / "eve-*.json")
    config.nom_client = "Cabinet Hoarau"
    return config


@pytest.fixture
def horloge():
    return Horloge()


@pytest.fixture
def sonde(config):
    s = Sonde(config)
    creer_utilisateur(s.base, "marie", BON)
    s.base.ecrire_meta("demarre_le", repr(T0))
    s.base.ecrire_meta("dernier_trafic", repr(T0 + 3590))
    yield s
    s.fermer()


@pytest.fixture
def appli(config, sonde, horloge):
    return creer_application(config, sonde=sonde, horloge=horloge)


@pytest.fixture
def anonyme(appli):
    return appli.test_client()


def jeton(client, chemin="/connexion"):
    page = client.get(chemin, base_url=HTTPS).get_data(as_text=True)
    return re.search(r'name="jeton" value="([^"]+)"', page).group(1)


def poster(client, chemin, donnees=None, avec_jeton=True, page_jeton="/"):
    donnees = dict(donnees or {})
    if avec_jeton:
        donnees["jeton"] = jeton(client, page_jeton)
    return client.post(chemin, data=donnees, base_url=HTTPS)


@pytest.fixture
def client(appli):
    c = appli.test_client()
    reponse = poster(c, "/connexion", {"identifiant": "marie", "mot_de_passe": BON}, page_jeton="/connexion")
    assert reponse.status_code == 302
    return c


@pytest.fixture
def donnees(sonde):
    inv, journal = sonde.inventaire, sonde.journal
    compta, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10", nom="PC-COMPTA")
    intrus, _ = inv.voir("192.168.1.66", T0)
    journal.signaler("signature", compta, "1", ELEVEE, T0 + 100, {"signature": "ET MALWARE test", "tiers": "203.0.113.66"})
    journal.signaler("nouvel_appareil", intrus, "", MOYENNE, T0 + 200, {})
    journal.signaler("hors_heures", intrus, "", FAIBLE, T0 + 5 * 3600, {"octets": 80_000_000})
    journal.signaler("non_chiffre", compta, "23", FAIBLE, T0, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    return {"compta": compta, "intrus": intrus}


# --------------------------------------------------------------- accès (F19)

@pytest.mark.parametrize("chemin", ["/", "/incidents", "/incidents/1", "/appareils", "/points-faibles", "/exceptions", "/rapport", "/compte"])
def test_pages_inaccessibles_sans_connexion(anonyme, chemin):
    reponse = anonyme.get(chemin, base_url=HTTPS)
    assert reponse.status_code == 302 and reponse.headers["Location"].endswith("/connexion")


def test_actions_inaccessibles_sans_connexion(anonyme, sonde, donnees):
    incident = sonde.journal.incidents()[0]["id"]
    reponse = poster(anonyme, f"/incidents/{incident}/resolu", page_jeton="/connexion")
    assert reponse.status_code == 302
    assert sonde.journal.incident(incident)["etat"] == "ouvert"


def test_connexion_refusee_avec_mauvais_mot_de_passe(anonyme):
    reponse = poster(anonyme, "/connexion", {"identifiant": "marie", "mot_de_passe": "faux"}, page_jeton="/connexion")
    assert reponse.status_code == 401
    page = reponse.get_data(as_text=True)
    assert "Identifiant ou mot de passe incorrect" in page
    assert anonyme.get("/", base_url=HTTPS).status_code == 302


def test_message_identique_pour_un_compte_inconnu(anonyme):
    """On ne révèle pas si l'identifiant existe."""
    a = poster(anonyme, "/connexion", {"identifiant": "marie", "mot_de_passe": "faux"}, page_jeton="/connexion")
    b = poster(anonyme, "/connexion", {"identifiant": "personne", "mot_de_passe": "faux"}, page_jeton="/connexion")
    extrait = lambda r: re.search(r'<p class="erreur">(.*?)</p>', r.get_data(as_text=True)).group(1)
    assert extrait(a) == extrait(b)


def test_verrouillage_par_l_interface(anonyme, config):
    for _ in range(config.web_verrouillage_essais):
        poster(anonyme, "/connexion", {"identifiant": "marie", "mot_de_passe": "faux"}, page_jeton="/connexion")
    reponse = poster(anonyme, "/connexion", {"identifiant": "marie", "mot_de_passe": BON}, page_jeton="/connexion")
    assert reponse.status_code == 401


def test_deconnexion(client):
    assert client.get("/", base_url=HTTPS).status_code == 200
    assert poster(client, "/deconnexion").status_code == 302
    assert client.get("/", base_url=HTTPS).status_code == 302


def test_session_expire(client, horloge, config):
    horloge.t += config.web_session_minutes * 60 + 1
    assert client.get("/", base_url=HTTPS).status_code == 302


def test_session_prolongee_par_l_activite(client, horloge, config):
    for _ in range(3):
        horloge.t += config.web_session_minutes * 60 - 60
        assert client.get("/", base_url=HTTPS).status_code == 200


# ------------------------------------------------------- sécurité (N5, F19)

def test_cookie_de_session_protege(appli):
    c = appli.test_client()
    reponse = poster(c, "/connexion", {"identifiant": "marie", "mot_de_passe": BON}, page_jeton="/connexion")
    cookie = [v for v in reponse.headers.getlist("Set-Cookie") if v.startswith("session=")][0]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_jeton_obligatoire_pour_toute_action(client, sonde, donnees):
    incident = sonde.journal.incidents()[0]["id"]
    assert poster(client, f"/incidents/{incident}/resolu", avec_jeton=False).status_code == 400
    assert client.post(f"/incidents/{incident}/resolu", data={"jeton": "faux"}, base_url=HTTPS).status_code == 400
    assert sonde.journal.incident(incident)["etat"] == "ouvert"


def test_jeton_obligatoire_a_la_connexion(anonyme):
    reponse = anonyme.post("/connexion", data={"identifiant": "marie", "mot_de_passe": BON}, base_url=HTTPS)
    assert reponse.status_code == 400


def test_entetes_de_securite(client):
    entetes = client.get("/", base_url=HTTPS).headers
    assert "default-src 'self'" in entetes["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in entetes["Content-Security-Policy"]
    assert entetes["X-Content-Type-Options"] == "nosniff"
    assert entetes["Referrer-Policy"] == "no-referrer"
    assert "no-store" in entetes["Cache-Control"]
    assert "max-age" in entetes["Strict-Transport-Security"]


def test_nom_d_appareil_piege_neutralise(client, sonde):
    """Le nom annoncé par un appareil (DHCP) est choisi par lui : il ne doit jamais s'exécuter."""
    ident, _ = sonde.inventaire.voir("192.168.1.99", T0, nom="<script>alert(1)</script>")
    sonde.journal.signaler("nouvel_appareil", ident, "", MOYENNE, T0, {})
    for chemin in ("/", "/appareils", "/incidents"):
        page = client.get(chemin, base_url=HTTPS).get_data(as_text=True)
        assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_aucune_ressource_externe(client, donnees):
    """N11 : la page ne charge rien depuis Internet."""
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    assert "http://" not in page and "https://" not in page and "<script" not in page


def test_cle_de_session_creee_et_protegee(appli, config):
    import os

    chemin = os.path.join(config.dossier_donnees, "cle_session")
    assert os.path.getsize(chemin) >= 32 and (os.stat(chemin).st_mode & 0o077) == 0


def test_cle_de_session_stable_entre_deux_demarrages(config, sonde, horloge):
    a = creer_application(config, sonde=sonde, horloge=horloge)
    b = creer_application(config, sonde=sonde, horloge=horloge)
    assert a.secret_key == b.secret_key


def test_sante_publique_sans_detail(anonyme):
    reponse = anonyme.get("/sante", base_url=HTTPS)
    assert reponse.status_code == 200 and reponse.get_json() == {"etat": "ok"}


def test_methodes_et_pages_inconnues(client):
    assert client.get("/nimporte", base_url=HTTPS).status_code == 404
    assert client.get("/incidents/9999", base_url=HTTPS).status_code == 404
    assert client.get("/deconnexion", base_url=HTTPS).status_code == 405


# ------------------------------------------------------ tableau de bord (F18)

def test_tableau_de_bord(client, donnees):
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    assert "Cabinet Hoarau" in page
    assert 'class="etat rouge"' in page and "action rapide" in page
    assert "attaque connue" in page and "Débranchez" in page          # incident élevé avec son conseil
    assert "Un nouvel appareil est apparu" in page                    # incident moyen
    assert page.index("attaque connue") < page.index("Un nouvel appareil est apparu")
    assert 'lang="fr"' in page


def test_tableau_de_bord_separe_les_signaux_faibles(client, donnees):
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    principal, _, information = page.partition("À titre d'information")
    assert "en dehors des heures de travail" in information
    assert "en dehors des heures de travail" not in principal


def test_tableau_de_bord_vert(client, sonde):
    sonde.inventaire.voir("192.168.1.10", T0)
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    assert 'class="etat vert"' in page and "Tout va bien" in page


def test_tableau_de_bord_signale_la_sonde_muette(client, sonde, horloge, config):
    horloge.t = T0 + 3590 + config.silence_max_minutes * 60 + 100
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    assert "ne reçoit plus de trafic" in page


def test_tableau_de_bord_indique_l_apprentissage(client, sonde):
    sonde.base.ecrire_meta("installe_le", repr(T0))
    page = client.get("/", base_url=HTTPS).get_data(as_text=True)
    assert "période d'apprentissage" in page


# ------------------------------------------------------------ incidents (F16)

def test_detail_d_un_incident(client, sonde, donnees):
    incident = [i for i in sonde.journal.incidents() if i["gravite"] == ELEVEE][0]
    page = client.get(f"/incidents/{incident['id']}", base_url=HTTPS).get_data(as_text=True)
    assert "ET MALWARE test" in page and "PC-COMPTA" in page and "29/05/2026 00:28" in page


def test_marquer_un_incident_normal(client, sonde, donnees):
    incident = [i for i in sonde.journal.incidents() if i["gravite"] == ELEVEE][0]["id"]
    reponse = poster(client, f"/incidents/{incident}/normal", {"commentaire": "test du prestataire"})
    assert reponse.status_code == 302
    assert sonde.journal.incident(incident)["etat"] == "normal"
    exceptions = client.get("/exceptions", base_url=HTTPS).get_data(as_text=True)
    assert "test du prestataire" in exceptions and "PC-COMPTA" in exceptions


def test_resoudre_un_incident(client, sonde, donnees):
    incident = sonde.journal.incidents()[0]["id"]
    assert poster(client, f"/incidents/{incident}/resolu").status_code == 302
    assert sonde.journal.incident(incident)["etat"] == "resolu"
    # une seconde demande sur un incident fermé est refusée proprement
    assert poster(client, f"/incidents/{incident}/resolu").status_code == 409


def test_supprimer_une_exception(client, sonde, donnees):
    incident = sonde.journal.incidents()[0]["id"]
    poster(client, f"/incidents/{incident}/normal")
    exception = sonde.journal.exceptions()[0]["id"]
    assert poster(client, f"/exceptions/{exception}/supprimer").status_code == 302
    assert sonde.journal.exceptions() == []


def test_liste_des_incidents_avec_historique(client, sonde, donnees):
    incident = sonde.journal.incidents()[0]["id"]
    poster(client, f"/incidents/{incident}/resolu")
    en_cours = client.get("/incidents", base_url=HTTPS).get_data(as_text=True)
    tout = client.get("/incidents?etat=tous", base_url=HTTPS).get_data(as_text=True)
    assert "attaque connue" not in en_cours and "attaque connue" in tout and "résolu" in tout


# ------------------------------------------------------------ appareils (F12)

def test_inventaire_affiche(client, donnees):
    page = client.get("/appareils", base_url=HTTPS).get_data(as_text=True)
    assert "PC-COMPTA" in page and "00:11:22:33:44:10" in page and "192.168.1.66" in page


def test_nommer_et_reconnaitre_un_appareil(client, sonde, donnees):
    reponse = poster(client, f"/appareils/{donnees['intrus']}", {"etiquette": "Imprimante accueil", "connu": "1"})
    assert reponse.status_code == 302
    appareil = sonde.inventaire.appareil(donnees["intrus"])
    assert appareil["etiquette"] == "Imprimante accueil" and appareil["connu"] is True


def test_reconnaitre_un_appareil_ferme_son_incident(client, sonde):
    ident, _ = sonde.inventaire.voir("192.168.1.77", T0)
    sonde.journal.signaler("nouvel_appareil", ident, "", MOYENNE, T0, {})
    poster(client, f"/appareils/{ident}", {"etiquette": "Tablette", "connu": "1"})
    assert sonde.journal.incidents(etat="ouvert") == []


def test_nom_trop_long_refuse_avec_message(client, donnees):
    reponse = poster(client, f"/appareils/{donnees['intrus']}", {"etiquette": "x" * 300})
    assert reponse.status_code == 400 and "trop long" in reponse.get_data(as_text=True)


def test_appareil_inconnu(client):
    assert poster(client, "/appareils/9999", {"etiquette": "x"}).status_code == 404


# ------------------------------------------------------- points faibles (F10)

def test_points_faibles_et_acceptation(client, sonde, donnees):
    page = client.get("/points-faibles", base_url=HTTPS).get_data(as_text=True)
    assert "Telnet" in page and "équivalent chiffré" in page
    faiblesse = sonde.journal.faiblesses()[0]["id"]
    assert poster(client, f"/points-faibles/{faiblesse}/accepter").status_code == 302
    assert sonde.journal.faiblesses() == []


# --------------------------------------------------------------- rapport (F17)

def test_telechargement_du_rapport(client, donnees):
    reponse = poster(client, "/rapport", {"jours": "30"})
    assert reponse.status_code == 200 and reponse.mimetype == "application/pdf"
    assert reponse.data[:5] == b"%PDF-"
    assert "attachment" in reponse.headers["Content-Disposition"] and ".pdf" in reponse.headers["Content-Disposition"]


def test_periode_de_rapport_invalide(client):
    assert poster(client, "/rapport", {"jours": "abc"}).status_code == 400
    assert poster(client, "/rapport", {"jours": "9999"}).status_code == 400


# ---------------------------------------------------------------- compte

def test_changer_son_mot_de_passe(client, sonde, config):
    from sonde.comptes import verifier

    nouveau = "Letchi-Combava-1946"
    refus = poster(client, "/compte", {"actuel": "faux", "nouveau": nouveau, "confirmation": nouveau})
    assert refus.status_code == 400
    court = poster(client, "/compte", {"actuel": BON, "nouveau": "court", "confirmation": "court"})
    assert court.status_code == 400 and "12 caractères" in court.get_data(as_text=True)
    differents = poster(client, "/compte", {"actuel": BON, "nouveau": nouveau, "confirmation": nouveau + "x"})
    assert differents.status_code == 400
    assert poster(client, "/compte", {"actuel": BON, "nouveau": nouveau, "confirmation": nouveau}).status_code == 302
    assert verifier(sonde.base, config, "marie", nouveau, T0) is True
