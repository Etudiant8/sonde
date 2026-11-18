# Installer la sonde chez un client

## Avant de venir

| Il faut | Détail |
| --- | --- |
| L'autorisation écrite du dirigeant | Voir [MODELES_JURIDIQUES.md](MODELES_JURIDIQUES.md). Sans elle, écouter un réseau est une infraction. |
| Une machine Linux du client | 4 cœurs, 8 Go de mémoire, 200 Go de disque (cible à confirmer), Docker installé |
| Deux cartes réseau | Une pour l'administration (interface web), une reliée au port miroir |
| Un port miroir | Sur le commutateur ou la box : copie du trafic vers la carte d'écoute |

Si le commutateur n'a pas de port miroir, la version 1 ne propose pas de solution logicielle :
il faut un commutateur administrable (quelques dizaines d'euros) ou un boîtier de dérivation (TAP)
entre la box et le commutateur.

## Installation

```bash
sudo sh scripts/installer.sh
```

Le script pose trois questions (nom du client, carte d'écoute, identifiant du compte), crée les
réglages dans `/etc/sonde`, génère un certificat HTTPS, construit les images et démarre la sonde.
Il affiche à la fin l'adresse de l'interface et l'empreinte du certificat.

La carte d'écoute ne doit avoir **aucune adresse IP** : elle reçoit seulement. Sur la machine hôte,
désactivez aussi IPv6 sur cette carte pour qu'elle n'émette rien :

```bash
sudo sysctl -w net.ipv6.conf.CARTE.disable_ipv6=1
```

## Première semaine : l'apprentissage

Pendant 168 heures, la sonde observe les habitudes du réseau. Elle signale déjà les attaques
connues, les balayages et les points faibles, mais pas encore les nouveaux appareils ni les écarts
de volume ou d'horaire. Pendant cette semaine :

1. nommez les appareils dans l'onglet **Appareils** et cochez « connu » ;
2. pour chaque incident sans gravité réelle, cliquez **C'est normal** : il ne reviendra plus.

## Commandes utiles

Toutes se lancent depuis le dossier du dépôt. Pour alléger :

```bash
alias sondectl='docker compose --project-directory deploiement --env-file /etc/sonde/sonde.env -f deploiement/docker-compose.yml'
```

| Besoin | Commande |
| --- | --- |
| État de la sonde | `sondectl exec sonde sonde etat` |
| Journal de la sonde | `sondectl logs --tail 50 sonde` |
| Rapport PDF | `sondectl exec sonde sonde rapport --jours 30 --sortie /tmp/rapport.pdf` (ou bouton dans l'interface) |
| Nouveau compte | `sondectl run --rm --no-deps sonde creer-compte IDENTIFIANT` |
| Mot de passe oublié | `sondectl run --rm --no-deps sonde mot-de-passe IDENTIFIANT` |
| Appliquer un réglage modifié | `sondectl restart sonde web` |

## Réglages

Le fichier `/etc/sonde/sonde.toml` est commenté ligne par ligne. Les plus utiles :

- `heure_ouverture`, `heure_fermeture`, `jours_ouvres` : horaires de travail du client ;
- `smtp_*` et `courriel_destinataires` : courriel pour les incidents de gravité élevée ;
- `export_syslog_*` ou `export_fichier` : envoi des alertes au centre de supervision d'un partenaire ;
- `fichier_fabricants` : fichier « manuf » de Wireshark, pour afficher le fabricant des appareils ;
- `fichier_pays` : fichier CSV « IP to Country Lite » de DB-IP, pour signaler un pays inhabituel.

## Mise à jour

Une mise à jour est une archive signée par nous. Le script refuse toute archive dont la signature
ne correspond pas à `scripts/cle_publique.pem`.

```bash
sudo sh scripts/mettre_a_jour.sh /chemin/sonde-X.Y.Z.tar.gz
```

À faire une seule fois, sur notre poste : créer notre paire de clés. La clé privée ne quitte
jamais notre coffre ; la clé publique est livrée avec la sonde dans `scripts/cle_publique.pem`.

```bash
openssl genpkey -algorithm ED25519 -out cle_privee.pem
```

```bash
openssl pkey -in cle_privee.pem -pubout -out scripts/cle_publique.pem
```

Pour signer une version :

```bash
openssl pkeyutl -sign -inkey cle_privee.pem -rawin -in sonde-X.Y.Z.tar.gz -out sonde-X.Y.Z.tar.gz.sig
```

Les règles de détection de Suricata se mettent à jour seules, une fois par jour, si la machine a
accès à Internet.

## Désinstallation

Supprime les conteneurs, les données, les journaux et les réglages. À faire en fin de test si le
client ne poursuit pas, puis confirmer la suppression par écrit.

```bash
sudo sh scripts/desinstaller.sh
```

## Sécurité : ce qu'il faut savoir

- L'interface n'est servie qu'en HTTPS, sur le port 8443 de la machine. Elle ne doit pas être
  ouverte vers Internet : c'est le pare-feu ou la box du client qui en décide.
- Le certificat est auto-signé : le navigateur avertit à la première visite. Comparez l'empreinte
  affichée avec celle donnée par l'installateur.
- Après 5 essais ratés, un compte est verrouillé 15 minutes.
- La sonde voit les destinations et les volumes, pas le contenu des échanges chiffrés.
- Par défaut, rien ne sort du réseau du client. Trois réglages font sortir des informations :
  le courriel, l'export et le signal de vie. Ne les activez qu'avec l'accord écrit du client.

## En cas de problème

| Symptôme | Vérifier |
| --- | --- |
| « La sonde ne reçoit plus de trafic » | Câble de la carte d'écoute, réglage du port miroir, `sondectl logs suricata` |
| Aucun appareil après une heure | Le port miroir copie-t-il bien les deux sens du trafic ? |
| Trop d'incidents | Marquer « C'est normal » ce qui l'est ; relever les seuils dans `sonde.toml` |
| Interface inaccessible | `sondectl ps`, puis `sondectl logs web` |
