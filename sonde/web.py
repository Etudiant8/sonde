"""Interface web locale, en français (besoins F12, F16 à F19, N5, N13).

Aucun JavaScript, aucune ressource chargée depuis Internet. Toutes les pages
exigent une connexion ; toutes les actions exigent un jeton anti-falsification.
"""
from __future__ import annotations

import hmac
import os
import secrets
import tempfile
import time
from datetime import datetime
from typing import Callable
from zoneinfo import ZoneInfo

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for

from .alertes import FAIBLE, MOYENNE, NOMS_GRAVITE
from .comptes import MotDePasseRefuse, changer_mot_de_passe, verifier
from .config import Config, charger
from .rapport import generer_rapport
from .traitement import Sonde

PAGES_PUBLIQUES = {"connexion", "sante", "static"}
NOMS_ETAT = {"ouvert": "à traiter", "normal": "jugé normal", "resolu": "résolu"}
MESSAGES_ETAT = {
    "rouge": "Un incident demande une action rapide.",
    "orange": "Des points demandent votre attention.",
    "vert": "Tout va bien : aucun incident en cours.",
}


def _cle_de_session(config: Config) -> bytes:
    chemin = os.path.join(config.dossier_donnees, "cle_session")
    os.makedirs(config.dossier_donnees, exist_ok=True)
    if not os.path.isfile(chemin) or os.path.getsize(chemin) < 32:
        descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descripteur, "wb") as f:
            f.write(secrets.token_bytes(48))
    with open(chemin, "rb") as f:
        return f.read()


def creer_application(config: Config, sonde: Sonde | None = None, horloge: Callable[[], float] = time.time) -> Flask:
    appli = Flask(__name__, template_folder="gabarits", static_folder="statique", static_url_path="/statique")
    appli.secret_key = _cle_de_session(config)
    appli.config.update(
        SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    sonde = sonde or Sonde(config)
    fuseau = ZoneInfo(config.fuseau)

    @appli.template_filter("date")
    def _date(quand: float | None) -> str:
        return datetime.fromtimestamp(quand, fuseau).strftime("%d/%m/%Y %H:%M") if quand else "-"

    @appli.context_processor
    def _commun():
        return {"client": config.nom_client, "jeton": _jeton(), "connecte": session.get("utilisateur"),
                "noms_etat": NOMS_ETAT, "noms_gravite": NOMS_GRAVITE}

    def _jeton() -> str:
        if "jeton" not in session:
            session["jeton"] = secrets.token_urlsafe(32)
        return session["jeton"]

    # ------------------------------------------------------------- contrôles
    @appli.before_request
    def _controles():
        maintenant = horloge()
        if session.get("utilisateur") and maintenant - session.get("vu_le", 0) > config.web_session_minutes * 60:
            session.clear()
        if request.method == "POST":
            recu = request.form.get("jeton", "")
            if not recu or not hmac.compare_digest(recu, session.get("jeton", "")):
                abort(400, "Jeton de sécurité manquant ou périmé : rechargez la page et recommencez.")
        if request.endpoint in PAGES_PUBLIQUES:
            return None
        if not session.get("utilisateur"):
            return redirect(url_for("connexion"))
        session["vu_le"] = maintenant
        return None

    @appli.after_request
    def _entetes(reponse):
        reponse.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        reponse.headers["X-Content-Type-Options"] = "nosniff"
        reponse.headers["X-Frame-Options"] = "DENY"
        reponse.headers["Referrer-Policy"] = "no-referrer"
        reponse.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.endpoint != "static":
            reponse.headers["Cache-Control"] = "no-store"
        return reponse

    @appli.errorhandler(400)
    @appli.errorhandler(404)
    @appli.errorhandler(405)
    @appli.errorhandler(409)
    @appli.errorhandler(413)
    def _erreur(erreur):
        messages = {404: "Cette page n'existe pas.", 405: "Cette action n'est pas possible ainsi.",
                    413: "Envoi trop volumineux."}
        texte = messages.get(erreur.code) or erreur.description
        return render_template("erreur.html", code=erreur.code, message=texte), erreur.code

    # -------------------------------------------------------------- connexion
    @appli.route("/connexion", methods=["GET", "POST"])
    def connexion():
        if request.method == "POST":
            identifiant = request.form.get("identifiant", "")
            if verifier(sonde.base, config, identifiant, request.form.get("mot_de_passe", ""), horloge()):
                session.clear()                       # nouvelle session à chaque connexion
                session["utilisateur"] = identifiant.strip().lower()
                session["vu_le"] = horloge()
                return redirect(url_for("accueil"))
            return render_template("connexion.html", erreur="Identifiant ou mot de passe incorrect.",
                                   essais=config.web_verrouillage_essais, minutes=config.web_verrouillage_minutes), 401
        return render_template("connexion.html", erreur=None, essais=config.web_verrouillage_essais,
                               minutes=config.web_verrouillage_minutes)

    @appli.post("/deconnexion")
    def deconnexion():
        session.clear()
        return redirect(url_for("connexion"))

    @appli.get("/sante")
    def sante():
        return {"etat": "ok"}

    # ------------------------------------------------------- tableau de bord
    @appli.get("/")
    def accueil():
        ouverts = sonde.journal.incidents(etat="ouvert")
        etat = sonde.journal.etat_general()
        return render_template(
            "accueil.html", etat=etat, message=MESSAGES_ETAT[etat], sante=sonde.sante(horloge()),
            principaux=[i for i in ouverts if i["gravite"] >= MOYENNE],
            mineurs=[i for i in ouverts if i["gravite"] == FAIBLE],
            nb_faiblesses=len(sonde.journal.faiblesses()),
            nb_inconnus=sum(1 for a in sonde.inventaire.lister() if not a["connu"]))

    # -------------------------------------------------------------- incidents
    @appli.get("/incidents")
    def incidents():
        tous = request.args.get("etat") == "tous"
        return render_template("incidents.html", tous=tous,
                               incidents=sonde.journal.incidents(etat=None if tous else "ouvert"))

    @appli.get("/incidents/<int:ident>")
    def incident(ident: int):
        fiche = sonde.journal.incident(ident)
        if not fiche:
            abort(404)
        return render_template("incident.html", incident=fiche, alertes=sonde.journal.alertes_de(ident))

    def _fermer(ident: int, action: Callable[[], None]):
        try:
            action()
        except KeyError:
            abort(404)
        except ValueError as erreur:
            abort(409, str(erreur) + ".")
        return redirect(url_for("incidents"))

    @appli.post("/incidents/<int:ident>/normal")
    def incident_normal(ident: int):
        commentaire = " ".join(request.form.get("commentaire", "").split())[:200]
        return _fermer(ident, lambda: sonde.journal.marquer_normal(ident, commentaire, horloge()))

    @appli.post("/incidents/<int:ident>/resolu")
    def incident_resolu(ident: int):
        return _fermer(ident, lambda: sonde.journal.resoudre(ident, horloge()))

    # -------------------------------------------------------------- appareils
    def _page_appareils(erreur: str | None = None):
        return render_template("appareils.html", appareils=sonde.inventaire.lister(), erreur=erreur)

    @appli.get("/appareils")
    def appareils():
        return _page_appareils()

    @appli.post("/appareils/<int:ident>")
    def appareil_modifier(ident: int):
        try:
            sonde.inventaire.nommer(ident, request.form.get("etiquette", ""))
            connu = request.form.get("connu") == "1"
            sonde.inventaire.marquer_connu(ident, connu)
        except KeyError:
            abort(404)
        except ValueError as erreur:
            return _page_appareils(str(erreur)), 400
        if connu:
            sonde.journal.appareil_reconnu(ident, horloge())
        return redirect(url_for("appareils"))

    # --------------------------------------------- points faibles, exceptions
    @appli.get("/points-faibles")
    def points_faibles():
        return render_template("points_faibles.html", faiblesses=sonde.journal.faiblesses())

    @appli.post("/points-faibles/<int:ident>/accepter")
    def point_faible_accepter(ident: int):
        try:
            sonde.journal.accepter_faiblesse(ident)
        except KeyError:
            abort(404)
        return redirect(url_for("points_faibles"))

    @appli.get("/exceptions")
    def exceptions():
        lignes = sonde.journal.exceptions()
        for e in lignes:
            appareil = sonde.inventaire.appareil(e["appareil_id"]) if e["appareil_id"] is not None else None
            e["appareil_nom"] = appareil["nom_affiche"] if appareil else "tous les appareils"
        return render_template("exceptions.html", exceptions=lignes)

    @appli.post("/exceptions/<int:ident>/supprimer")
    def exception_supprimer(ident: int):
        sonde.journal.supprimer_exception(ident)
        return redirect(url_for("exceptions"))

    # ---------------------------------------------------------------- rapport
    @appli.route("/rapport", methods=["GET", "POST"])
    def rapport():
        if request.method == "GET":
            return render_template("rapport.html")
        try:
            jours = int(request.form.get("jours", ""))
        except ValueError:
            abort(400, "Période invalide.")
        if not 1 <= jours <= 365:
            abort(400, "La période doit être comprise entre 1 et 365 jours.")
        maintenant = horloge()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            chemin = f.name
        try:
            generer_rapport(sonde, chemin, maintenant - jours * 86400, maintenant, maintenant)
            with open(chemin, "rb") as f:
                contenu = f.read()
        finally:
            os.unlink(chemin)
        import io

        nom = "rapport-sonde-" + datetime.fromtimestamp(maintenant, fuseau).strftime("%Y-%m-%d") + ".pdf"
        return send_file(io.BytesIO(contenu), mimetype="application/pdf", as_attachment=True, download_name=nom)

    # ----------------------------------------------------------------- compte
    @appli.route("/compte", methods=["GET", "POST"])
    def compte():
        if request.method == "GET":
            return render_template("compte.html", erreur=None)
        utilisateur = session["utilisateur"]
        nouveau = request.form.get("nouveau", "")
        erreur = None
        if not verifier(sonde.base, config, utilisateur, request.form.get("actuel", ""), horloge()):
            erreur = "Le mot de passe actuel est incorrect."
        elif nouveau != request.form.get("confirmation", ""):
            erreur = "Les deux saisies du nouveau mot de passe sont différentes."
        else:
            try:
                changer_mot_de_passe(sonde.base, utilisateur, nouveau)
            except MotDePasseRefuse as refus:
                erreur = str(refus)
        if erreur:
            return render_template("compte.html", erreur=erreur), 400
        return redirect(url_for("accueil"))

    return appli


def application() -> Flask:
    """Point d'entrée pour gunicorn : ``gunicorn 'sonde.web:application()'``."""
    return creer_application(charger(os.environ.get("SONDE_CONFIG") or None))
