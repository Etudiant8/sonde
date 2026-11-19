"""Base de données locale (SQLite). Tout reste sur la machine du client (N11)."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS appareils (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE,
    nom_reseau TEXT NOT NULL DEFAULT '',
    etiquette TEXT NOT NULL DEFAULT '',
    fabricant TEXT NOT NULL DEFAULT '',
    connu INTEGER NOT NULL DEFAULT 0,
    passerelle INTEGER NOT NULL DEFAULT 0,
    premiere_vue REAL NOT NULL,
    derniere_vue REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS adresses (
    ip TEXT PRIMARY KEY,
    appareil_id INTEGER NOT NULL REFERENCES appareils(id) ON DELETE CASCADE,
    derniere_vue REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS adresses_appareil ON adresses(appareil_id);

CREATE TABLE IF NOT EXISTS noms_dns (ip TEXT PRIMARY KEY, nom TEXT NOT NULL, vu REAL NOT NULL);

CREATE TABLE IF NOT EXISTS destinations (
    appareil_id INTEGER NOT NULL, ip TEXT NOT NULL,
    premiere_vue REAL NOT NULL, derniere_vue REAL NOT NULL,
    PRIMARY KEY (appareil_id, ip)
);
CREATE TABLE IF NOT EXISTS pays_vus (pays TEXT PRIMARY KEY, premiere_vue REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sortie_jour (
    appareil_id INTEGER NOT NULL, jour TEXT NOT NULL, octets INTEGER NOT NULL,
    PRIMARY KEY (appareil_id, jour)
);
CREATE TABLE IF NOT EXISTS hors_heures (
    appareil_id INTEGER NOT NULL, jour TEXT NOT NULL, octets INTEGER NOT NULL,
    PRIMARY KEY (appareil_id, jour)
);
CREATE TABLE IF NOT EXISTS flux_recents (
    quand REAL NOT NULL, ip_src TEXT NOT NULL, ip_dst TEXT NOT NULL,
    port_dst INTEGER NOT NULL, etabli INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS flux_recents_src ON flux_recents(ip_src, quand);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    appareil_id INTEGER,
    gravite INTEGER NOT NULL,               -- 1 faible, 2 moyenne, 3 élevée
    etat TEXT NOT NULL DEFAULT 'ouvert',    -- ouvert | normal | resolu
    resume TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    ouvert_le REAL NOT NULL,
    maj_le REAL NOT NULL,
    ferme_le REAL,
    gravite_notifiee INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_etat ON incidents(etat, appareil_id);

CREATE TABLE IF NOT EXISTS alertes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    categorie TEXT NOT NULL,                -- incident | faiblesse
    appareil_id INTEGER,
    cle TEXT NOT NULL DEFAULT '',
    gravite INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}',      -- JSON
    premiere_vue REAL NOT NULL,
    derniere_vue REAL NOT NULL,
    nombre INTEGER NOT NULL DEFAULT 1,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    exportee INTEGER NOT NULL DEFAULT 0,
    etat TEXT NOT NULL DEFAULT 'ouverte'    -- ouverte | normale (pour les faiblesses)
);
CREATE INDEX IF NOT EXISTS alertes_doublon ON alertes(type, appareil_id, cle, derniere_vue);
CREATE INDEX IF NOT EXISTS alertes_incident ON alertes(incident_id);

CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    appareil_id INTEGER,                    -- NULL = tous les appareils
    cle TEXT NOT NULL DEFAULT '',
    commentaire TEXT NOT NULL DEFAULT '',
    creee_le REAL NOT NULL,
    UNIQUE (type, appareil_id, cle)
);

CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifiant TEXT NOT NULL UNIQUE,
    hachage TEXT NOT NULL,
    essais INTEGER NOT NULL DEFAULT 0,
    verrou_jusqu REAL NOT NULL DEFAULT 0
);
"""


class Base:
    """Connexion SQLite partagée, protégée par un verrou (sonde + interface web)."""

    def __init__(self, chemin: str | Path) -> None:
        self.chemin = Path(chemin)
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        self._verrou = threading.RLock()
        self._lots = 0
        self._cx = sqlite3.connect(str(self.chemin), check_same_thread=False, timeout=30)
        self._cx.row_factory = sqlite3.Row
        self._cx.execute("PRAGMA journal_mode=WAL")
        self._cx.execute("PRAGMA foreign_keys=ON")
        self._cx.execute("PRAGMA busy_timeout=30000")

    def initialiser(self) -> None:
        with self._verrou:
            self._cx.executescript(SCHEMA)
            self._cx.commit()
        try:
            self.chemin.chmod(0o600)   # lisible par le seul compte de la sonde
        except OSError:
            pass

    def fermer(self) -> None:
        with self._verrou:
            self._cx.close()

    # --- requêtes ---
    def executer(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._verrou:
            curseur = self._cx.execute(sql, params)
            if self._lots == 0:
                self._cx.commit()
            return curseur

    def lot(self):
        """Regroupe plusieurs écritures en une seule transaction : ``with base.lot():``"""
        return _Lot(self)

    def un(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._verrou:
            return self._cx.execute(sql, params).fetchone()

    def tous(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._verrou:
            return self._cx.execute(sql, params).fetchall()

    # --- petites valeurs de fonctionnement ---
    def lire_meta(self, cle: str, defaut: str | None = None) -> str | None:
        ligne = self.un("SELECT valeur FROM meta WHERE cle=?", (cle,))
        return ligne["valeur"] if ligne else defaut

    def ecrire_meta(self, cle: str, valeur: str) -> None:
        self.executer("INSERT INTO meta(cle, valeur) VALUES(?, ?) "
                      "ON CONFLICT(cle) DO UPDATE SET valeur=excluded.valeur", (cle, str(valeur)))


class _Lot:
    def __init__(self, base: Base) -> None:
        self.base = base

    def __enter__(self):
        self.base._verrou.acquire()
        self.base._lots += 1
        return self.base

    def __exit__(self, type_exc, exc, trace):
        try:
            self.base._lots -= 1
            if type_exc is not None:
                self.base._cx.rollback()
            elif self.base._lots == 0:
                self.base._cx.commit()
        finally:
            self.base._verrou.release()
        return False
