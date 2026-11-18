"""Rapport PDF remis au client (besoin F17)."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fpdf import FPDF

from .alertes import ELEVEE, NOMS_GRAVITE

POLICES_DEJAVU = ("/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF")
NOMS_ETAT = {"ouvert": "à traiter", "normal": "jugé normal", "resolu": "résolu"}
COULEURS = {3: (192, 57, 43), 2: (211, 126, 20), 1: (90, 100, 110)}
_REMPLACEMENTS = {"œ": "oe", "Œ": "OE", "€": "EUR", "–": "-", "—": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "…": "..."}


def donnees_rapport(sonde, debut: float, fin: float, maintenant: float) -> dict:
    """Tout le contenu du rapport, indépendamment de la mise en page."""
    appareils = sonde.inventaire.lister()
    incidents = [i for i in sonde.journal.incidents() if i["maj_le"] >= debut and i["ouvert_le"] <= fin]
    faiblesses = sonde.journal.faiblesses()
    inconnus = sum(1 for a in appareils if not a["connu"])

    recommandations: list[str] = []

    def ajouter(texte: str) -> None:
        if texte not in recommandations:
            recommandations.append(texte)

    for i in incidents:                      # déjà triés du plus grave au moins grave
        if i["etat"] == "ouvert":
            ajouter(i["action"])
    for f in faiblesses:
        ajouter(f["conseil"])
    if inconnus == 1:
        ajouter("1 appareil du réseau n'est pas encore identifié : vérifiez qu'il vous appartient.")
    elif inconnus > 1:
        ajouter(f"{inconnus} appareils du réseau ne sont pas encore identifiés : vérifiez qu'ils vous appartiennent.")

    return {
        "client": sonde.config.nom_client,
        "debut": debut, "fin": fin, "genere_le": maintenant,
        "etat": sonde.journal.etat_general(),
        "sante": sonde.sante(maintenant),
        "synthese": {
            "appareils": len(appareils), "appareils_inconnus": inconnus,
            "incidents": len(incidents),
            "incidents_eleves": sum(1 for i in incidents if i["gravite"] == ELEVEE),
            "incidents_ouverts": sum(1 for i in incidents if i["etat"] == "ouvert"),
            "points_faibles": len(faiblesses),
        },
        "incidents": incidents,
        "points_faibles": faiblesses,
        "appareils": appareils,
        "recommandations": recommandations,
    }


def _dossier_police() -> str | None:
    for dossier in POLICES_DEJAVU:
        if os.path.isfile(os.path.join(dossier, "DejaVuSans.ttf")) and os.path.isfile(os.path.join(dossier, "DejaVuSans-Bold.ttf")):
            return dossier
    return None


class _Rapport(FPDF):
    def __init__(self, client: str, police: str | None) -> None:
        super().__init__(format="A4")
        self.client = client
        self.etendue = bool(police)
        if police:
            self.add_font("Texte", "", os.path.join(police, "DejaVuSans.ttf"))
            self.add_font("Texte", "B", os.path.join(police, "DejaVuSans-Bold.ttf"))
            self.nom_police = "Texte"
        else:
            self.nom_police = "Helvetica"
        self.set_auto_page_break(True, margin=18)
        self.set_margins(15, 15, 15)

    def t(self, texte) -> str:
        """Texte affichable avec la police choisie."""
        texte = str(texte)
        if self.etendue:
            # la police ne connaît pas tous les alphabets : les signes inconnus deviennent « ? »
            return "".join(c if ord(c) < 0x2E80 else "?" for c in texte)
        for ancien, nouveau in _REMPLACEMENTS.items():
            texte = texte.replace(ancien, nouveau)
        return texte.encode("latin-1", errors="replace").decode("latin-1")

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font(self.nom_police, "", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, self.t(f"{self.client} - Document confidentiel - page {self.page_no()}"), align="C")

    def titre(self, texte: str) -> None:
        self.ln(3)
        self.set_font(self.nom_police, "B", 13)
        self.set_text_color(20, 40, 70)
        self.cell(0, 8, self.t(texte), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(20, 40, 70)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def paragraphe(self, texte: str, gras: bool = False, taille: float = 10, couleur=(30, 30, 30)) -> None:
        self.set_font(self.nom_police, "B" if gras else "", taille)
        self.set_text_color(*couleur)
        self.multi_cell(0, taille * 0.5, self.t(texte), new_x="LMARGIN", new_y="NEXT")


def generer_rapport(sonde, chemin, debut: float, fin: float, maintenant: float, police: str | None = "auto") -> dict:
    """Écrit le rapport PDF dans ``chemin`` et renvoie ses données."""
    d = donnees_rapport(sonde, debut, fin, maintenant)
    fuseau = ZoneInfo(sonde.config.fuseau)

    def date(quand: float, heure: bool = True) -> str:
        return datetime.fromtimestamp(quand, fuseau).strftime("%d/%m/%Y %H:%M" if heure else "%d/%m/%Y")

    pdf = _Rapport(d["client"], _dossier_police() if police == "auto" else police)
    pdf.set_title(f"Rapport de surveillance réseau - {d['client']}")
    pdf.add_page()

    pdf.set_font(pdf.nom_police, "B", 18)
    pdf.set_text_color(20, 40, 70)
    pdf.cell(0, 10, pdf.t("Rapport de surveillance du réseau"), new_x="LMARGIN", new_y="NEXT")
    pdf.paragraphe(d["client"], gras=True, taille=13)
    pdf.paragraphe(f"Période du {date(debut, False)} au {date(fin, False)} - rapport établi le {date(maintenant)}",
                   taille=9, couleur=(90, 90, 90))

    # --- Synthèse ---
    s = d["synthese"]
    pdf.titre("Synthèse")
    verdict = {"rouge": "Au moins un incident de gravité élevée demande une action rapide.",
               "orange": "Des points demandent votre attention, sans urgence immédiate.",
               "vert": "Aucun incident en cours ne demande d'action."}[d["etat"]]
    pdf.paragraphe(verdict, gras=True, couleur=COULEURS[{"rouge": 3, "orange": 2, "vert": 1}[d["etat"]]])
    pdf.ln(1)
    pdf.paragraphe(
        f"Appareils vus sur le réseau : {s['appareils']} (dont {s['appareils_inconnus']} non identifiés)\n"
        f"Incidents sur la période : {s['incidents']} (dont {s['incidents_eleves']} de gravité élevée, {s['incidents_ouverts']} à traiter)\n"
        f"Points faibles relevés : {s['points_faibles']}")
    if d["sante"]["apprentissage"]:
        pdf.ln(1)
        pdf.paragraphe("La sonde est encore en période d'apprentissage : elle observe les habitudes du réseau, "
                       "et certains signaux (volumes, horaires, nouveaux appareils) ne sont pas encore remontés.",
                       taille=9, couleur=(90, 90, 90))

    # --- Incidents ---
    pdf.titre("Incidents")
    if not d["incidents"]:
        pdf.paragraphe("Aucun incident relevé sur la période.")
    for i in d["incidents"]:
        pdf.paragraphe(f"{date(i['ouvert_le'])} - gravité {NOMS_GRAVITE[i['gravite']]} - {NOMS_ETAT[i['etat']]}",
                       gras=True, taille=9.5, couleur=COULEURS[i["gravite"]])
        pdf.paragraphe(i["resume"], taille=9.5)
        pdf.paragraphe("Conseil : " + i["action"], taille=9.5, couleur=(60, 60, 60))
        pdf.ln(2.5)

    # --- Points faibles ---
    pdf.titre("Points faibles")
    if not d["points_faibles"]:
        pdf.paragraphe("Aucun point faible relevé.")
    for f in d["points_faibles"]:
        pdf.paragraphe(f"[{NOMS_GRAVITE[f['gravite']]}] {f['texte']}", taille=9.5)
        pdf.ln(1)

    # --- Recommandations ---
    pdf.titre("Recommandations")
    if not d["recommandations"]:
        pdf.paragraphe("Aucune action n'est nécessaire pour le moment.")
    for n, texte in enumerate(d["recommandations"], 1):
        pdf.paragraphe(f"{n}. {texte}", taille=9.5)
        pdf.ln(1)

    # --- Inventaire ---
    if pdf.get_y() > pdf.h - 60:          # pas de titre isolé en bas de page
        pdf.add_page()
    pdf.titre("Inventaire des appareils")
    if not d["appareils"]:
        pdf.paragraphe("Aucun appareil vu sur le réseau pour le moment.")
    else:
        pdf.set_font(pdf.nom_police, "", 7.5)
        pdf.set_text_color(30, 30, 30)
        pdf.set_draw_color(180, 180, 180)
        with pdf.table(col_widths=(50, 32, 36, 30, 14, 28), line_height=4.5, text_align="LEFT",
                       headings_style=_style_entete(pdf)) as tableau:
            ligne = tableau.row()
            for entete in ("Nom", "Adresse", "Adresse MAC", "Fabricant", "Connu", "Vu le"):
                ligne.cell(pdf.t(entete))
            for a in d["appareils"]:
                ligne = tableau.row()
                nom = a["nom_affiche"] + (" (routeur)" if a["passerelle"] else "")
                for valeur in (nom, a["adresses"][0] if a["adresses"] else "-", a["mac"] or "-",
                               a["fabricant"] or "-", "oui" if a["connu"] else "non", date(a["derniere_vue"])):
                    ligne.cell(pdf.t(valeur))

    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(chemin))
    return d


def _style_entete(pdf: _Rapport):
    from fpdf.fonts import FontFace

    return FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=(20, 40, 70))
