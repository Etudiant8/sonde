# Sonde réseau pour TPE/PME

Sonde logicielle installée **chez le client** : elle écoute le réseau par un port miroir, tient
l'inventaire des appareils, repère ce qui est anormal et l'explique en français clair à un
dirigeant qui n'est pas informaticien. Aucune donnée ne quitte la machine du client.

- Capture et règles d'attaques connues : [Suricata](https://suricata.io) (logiciel libre).
- Analyse, incidents, interface web, rapport PDF : ce dépôt (Python, SQLite).

| Document | Contenu |
| --- | --- |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Installer, régler, mettre à jour, désinstaller |
| [docs/SUIVI_DES_BESOINS.md](docs/SUIVI_DES_BESOINS.md) | État de chaque besoin du cahier, preuve et limites |
| [docs/MODELES_JURIDIQUES.md](docs/MODELES_JURIDIQUES.md) | Documents à faire signer avant un test (à faire relire par un juriste) |

## Fonctionnement

```
port miroir -> Suricata (conteneur) -> journaux eve-AAAA-MM-JJ.json
                                           |
                 sonde surveiller (conteneur) : lecture -> inventaire -> détecteurs -> incidents
                                           |                                    |
                                     base SQLite locale                courriel, export SOC
                                           |
                 sonde web (conteneur) : interface HTTPS, rapport PDF
```

| Fichier | Rôle |
| --- | --- |
| `sonde/lecture.py` | Lit les journaux Suricata (et Zeek en option) |
| `sonde/inventaire.py` | Appareils : adresses, MAC, nom, fabricant, « connu » |
| `sonde/detection.py` | Détecteurs : attaque connue, nouvel appareil, balayage, volume, horaires, destinations, points faibles |
| `sonde/alertes.py` | Regroupe les signaux en incidents, calcule la gravité, gère les exceptions |
| `sonde/explications.py` | Phrases et conseils en français |
| `sonde/traitement.py` | Cycle complet, reprise après coupure, santé de la sonde, purge |
| `sonde/rapport.py`, `notification.py`, `export.py` | PDF, courriel, export JSON/syslog |
| `sonde/web.py`, `comptes.py` | Interface web et comptes |
| `sonde/cli.py` | Commande `sonde` |
| `deploiement/`, `scripts/` | Images Docker, installation, mise à jour signée, désinstallation |

## Développer

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e ".[dev]" pypdf
```

```bash
.venv/bin/python -m pytest
```

Les tests d'intégration lancent le vrai Suricata s'il est installé (`apt install suricata`) ;
sinon ils sont sautés. Le test de validité du fichier Compose demande Docker.

### Règle de travail : test d'abord

Chaque besoin a ses tests, écrits **avant** le code. Pour ajouter un détecteur :

1. écrire dans `tests/test_detection.py` un test qui rejoue des événements et attend l'alerte ;
2. le voir échouer ;
3. ajouter le type dans `sonde/explications.py` (phrase + conseil) et la détection dans `sonde/detection.py` ;
4. relancer toute la suite.

Un défaut trouvé en essai réel commence toujours par un test qui le reproduit.

### Rejouer le scénario d'essai

`tests/outils/fabrique_pcap.py` fabrique une capture avec un poste compromis, un balayage
interne, du Telnet, un bureau à distance exposé et un gros envoi. Elle se rejoue sur une carte
réseau avec `tcpreplay` pour essayer une installation complète.
