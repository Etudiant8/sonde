"""F17 : rapport PDF remis au client."""
import pytest
from pypdf import PdfReader

from sonde.alertes import ELEVEE, FAIBLE, MOYENNE
from sonde.rapport import donnees_rapport, generer_rapport
from sonde.traitement import Sonde

from .conftest import T0

JOUR = 86400


@pytest.fixture
def sonde(config, tmp_path):
    config.dossier_donnees = str(tmp_path / "donnees")
    config.journal_eve = str(tmp_path / "eve-*.json")
    config.nom_client = "Cabinet Hoarau"
    s = Sonde(config)
    yield s
    s.fermer()


@pytest.fixture
def peuplee(sonde):
    inv, journal = sonde.inventaire, sonde.journal
    compta, _ = inv.voir("192.168.1.10", T0, mac="00:11:22:33:44:10", nom="PC-COMPTA")
    serveur, _ = inv.voir("192.168.1.20", T0, mac="00:11:22:33:44:20")
    inconnu, _ = inv.voir("192.168.1.66", T0 + 3600)
    inv.nommer(serveur, "Serveur de fichiers"); inv.marquer_connu(serveur, True); inv.marquer_connu(compta, True)
    journal.signaler("signature", compta, "1", ELEVEE, T0 + 100, {"signature": "ET MALWARE test", "tiers": "203.0.113.66"})
    journal.signaler("balayage", inconnu, "port:445", MOYENNE, T0 + 3700, {"port": 445, "machines": 15})
    journal.signaler("non_chiffre", serveur, "23", FAIBLE, T0, {"port": 23, "protocole": "Telnet"}, categorie="faiblesse")
    journal.signaler("service_expose", serveur, "3389", MOYENNE, T0, {"port": 3389, "service": "rdp"}, categorie="faiblesse")
    return sonde


def texte_pdf(chemin) -> str:
    # les retours à la ligne de mise en page sont ramenés à des espaces
    return " ".join("\n".join(page.extract_text() for page in PdfReader(str(chemin)).pages).split())


def test_donnees_du_rapport(peuplee):
    d = donnees_rapport(peuplee, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    assert d["client"] == "Cabinet Hoarau"
    assert d["synthese"] == {"appareils": 3, "appareils_inconnus": 1, "incidents": 2, "incidents_eleves": 1,
                             "incidents_ouverts": 2, "points_faibles": 2}
    assert [i["gravite_nom"] for i in d["incidents"]] == ["élevée", "moyenne"]
    assert [a["nom_affiche"] for a in d["appareils"]][0] in ("192.168.1.66", "PC-COMPTA", "Serveur de fichiers")
    assert len(d["points_faibles"]) == 2 and d["points_faibles"][0]["type"] == "service_expose"


def test_recommandations_classees_et_sans_doublon(peuplee):
    d = donnees_rapport(peuplee, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    recos = d["recommandations"]
    assert len(recos) == len(set(recos))
    assert recos[0].startswith("Débranchez")                         # l'incident élevé d'abord
    assert any("1 appareil" in r and "identifi" in r.lower() for r in recos)
    assert any("VPN" in r for r in recos) and any("chiffré" in r for r in recos)


def test_periode_filtre_les_incidents(peuplee):
    d = donnees_rapport(peuplee, T0 + 2 * JOUR, T0 + 3 * JOUR, T0 + 3 * JOUR)
    assert d["incidents"] == [] and d["synthese"]["incidents"] == 0
    assert d["synthese"]["points_faibles"] == 2                       # les points faibles durables restent


def test_pdf_genere_et_lisible(peuplee, tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(peuplee, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    assert chemin.read_bytes()[:5] == b"%PDF-"
    texte = texte_pdf(chemin)
    for attendu in ("Cabinet Hoarau", "PC-COMPTA", "Serveur de fichiers", "00:11:22:33:44:10", "attaque connue",
                    "15 machines", "Telnet", "3389", "Recommandations", "élevée", "Débranchez"):
        assert attendu in texte, attendu


def test_pdf_reseau_sans_incident(sonde, tmp_path):
    sonde.inventaire.voir("192.168.1.10", T0)
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(sonde, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    texte = texte_pdf(chemin)
    assert "Aucun incident" in texte and "Aucun point faible" in texte


def test_pdf_reseau_vide(sonde, tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(sonde, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    assert "Aucun appareil" in texte_pdf(chemin)


def test_pdf_caracteres_speciaux(sonde, tmp_path):
    ident, _ = sonde.inventaire.voir("192.168.1.10", T0)
    sonde.inventaire.nommer(ident, "Poste <Marie> & Cie – cœur 100 € 日本")
    sonde.journal.signaler("signature", ident, "1", ELEVEE, T0, {"signature": "règle « spéciale » ’ — ✓"})
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(sonde, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    assert "Marie" in texte_pdf(chemin)


def test_pdf_sans_police_etendue(peuplee, tmp_path):
    """Sans police DejaVu sur la machine, le rapport sort quand même (accents conservés)."""
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(peuplee, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR, police=None)
    texte = texte_pdf(chemin)
    assert "élevée" in texte and "Cabinet Hoarau" in texte


def test_pdf_beaucoup_d_appareils_plusieurs_pages(sonde, tmp_path):
    for i in range(1, 121):
        sonde.inventaire.voir(f"192.168.1.{i}", T0 + i)
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(sonde, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    lecteur = PdfReader(str(chemin))
    assert len(lecteur.pages) >= 3 and "192.168.1.120" in texte_pdf(chemin)


def test_dates_en_heure_locale(peuplee, tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(peuplee, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    # T0 + 100 s = 28 mai 2026 20:28 UTC = 29 mai 2026 00:28 à La Réunion
    assert "29/05/2026 00:28" in texte_pdf(chemin)


def test_titre_de_l_inventaire_jamais_seul_en_bas_de_page(sonde, tmp_path):
    """Le titre et le début du tableau doivent être sur la même page."""
    for i in range(1, 6):
        ident, _ = sonde.inventaire.voir(f"192.168.1.{i}", T0)
        for j in range(3):
            sonde.journal.signaler("signature", ident, str(j), MOYENNE, T0 + j * 3 * 3600, {"signature": f"règle {j}"})
    chemin = tmp_path / "rapport.pdf"
    generer_rapport(sonde, chemin, T0 - JOUR, T0 + JOUR, T0 + JOUR)
    for page in PdfReader(str(chemin)).pages:
        texte = " ".join(page.extract_text().split())
        if "Inventaire des appareils" in texte:
            assert "Adresse MAC" in texte
            break
    else:
        raise AssertionError("titre de l'inventaire introuvable")
