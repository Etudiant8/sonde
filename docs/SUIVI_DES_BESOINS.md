# Suivi des besoins — version 0.1.0

État de chaque besoin du cahier, avec la preuve et ce qui reste à faire. Trois états :
**Couvert** (développé et vérifié), **Partiel** (développé, avec une limite), **À faire**.

Sur 34 besoins : 23 couverts, 10 partiels, 1 à faire.

## Comment c'est vérifié

| Vérification | Résultat |
| --- | --- |
| Tests automatiques (écrits avant le code) | 270 tests, tous verts ; 95 % du code exercé |
| Vrai Suricata 7.0.3 sur une capture fabriquée | Vert, relancé à chaque passage de la suite |
| Installation réelle par `installer.sh`, capture en direct sur une carte virtuelle, interface en HTTPS dans un navigateur | Fait sur la version finale |
| Reprise après arrêt brutal des conteneurs, mise à jour signée, désinstallation | Faits sur l'installation réelle |
| Charge : 300 000 connexions (une journée, 60 postes) | 40 s, 7 500 événements/s, 54 Mo de mémoire |

Ce qui **n'a pas** été vérifié : un vrai réseau de client, un vrai port miroir, les règles publiques
Emerging Threats (téléchargement bloqué dans l'environnement de développement), un vrai serveur de
courriel, Zeek en fonctionnement réel.

## Besoins fonctionnels

| N° | Besoin | État | Preuve et limite |
| --- | --- | --- | --- |
| F1 | Écoute par port miroir | Couvert | Suricata en écoute sur la carte ; essai en direct sur carte virtuelle. Pas encore essayé sur un vrai commutateur. |
| F2 | Solution sans port miroir | À faire | Aucune solution logicielle. Contournement matériel décrit dans INSTALLATION.md (commutateur administrable ou TAP). |
| F3 | Journal des connexions, DNS, certificats, fichiers | Partiel | Fait par Suricata (connexions, DNS, TLS, HTTP, DHCP, fichiers). La lecture des journaux Zeek existe mais n'est testée que sur des échantillons. |
| F4 | Attaques connues (règles libres) | Partiel | Chaîne vérifiée avec une règle locale. Le téléchargement quotidien des règles Emerging Threats est en place mais n'a pas pu être essayé ici. |
| F5 | Nouvel appareil | Couvert | `test_detection.py` ; silencieux pendant l'apprentissage. |
| F6 | Volume sortant inhabituel | Couvert | Seuil fixe, puis 3 fois l'habitude de l'appareil. |
| F7 | Balayage interne | Couvert | Machines sur un port, ou ports sur une machine, fenêtre glissante de 5 minutes. Ne voit pas un balayage ARP ni un balayage vers Internet. |
| F8 | Destinations jamais vues, pays inhabituels | Partiel | Connexion directe à une adresse inconnue sur un port inhabituel : couvert. Pays : demande un fichier DB-IP non fourni. |
| F9 | Activité à des heures anormales | Couvert | Horaires réglables, fuseau de La Réunion, appareils habituellement actifs la nuit exclus. |
| F10 | Services exposés, protocoles non chiffrés | Couvert | Affichés dans « Points faibles » et dans le rapport. |
| F11 | Inventaire (IP, MAC, fabricant, nom, dates) | Partiel | Tout sauf le fabricant, qui demande le fichier « manuf » de Wireshark non fourni. |
| F12 | Nommer un appareil, le marquer connu | Couvert | Interface web. |
| F13 | Regrouper les alertes en incidents | Couvert | Même appareil, 2 heures. |
| F14 | Gravité faible, moyenne, élevée | Couvert | La gravité monte d'un cran quand deux signaux différents touchent le même appareil. |
| F15 | Explication claire et action | Couvert | Phrases relues sur l'essai réel ; à faire relire par un vrai dirigeant. |
| F16 | Marquer une alerte comme normale | Couvert | Crée une exception, supprimable. |
| F17 | Rapport PDF | Couvert | Exemple : `docs/apercus/exemple-rapport.pdf`. |
| F18 | Page d'accueil avec l'état général | Couvert | Aperçu : `docs/apercus/tableau-de-bord.png`. |
| F19 | Accès par identifiant et mot de passe fort | Couvert | 12 caractères, hachage scrypt, verrouillage après 5 essais. |
| F20 | Courriel pour les incidents élevés | Partiel | Testé avec un faux serveur ; à essayer avec le vrai serveur du client. |
| F21 | Export syslog ou JSON | Couvert | Testé en UDP, TCP et fichier. |

## Besoins non fonctionnels

| N° | Besoin | État | Preuve et limite |
| --- | --- | --- | --- |
| N1 | Installation en moins d'une heure | Couvert | 16 secondes ici images déjà construites, environ 2 minutes à la première construction. Le mode avec questions n'a pas été essayé à la main. |
| N2 | Machine du client (4 cœurs, 8 Go, 200 Go) | Partiel | La sonde est très légère (54 Mo). Le besoin réel de Suricata sur un vrai trafic reste à mesurer. |
| N3 | Disque jamais plein | Couvert | Purge à 90 jours et plafond de 20 Go sur les journaux. |
| N4 | Aucun port ouvert depuis Internet | Couvert | Un seul port (8443, HTTPS). Le fermer vers Internet relève du pare-feu du client. |
| N5 | HTTPS, mots de passe hachés | Couvert | Certificat auto-signé : avertissement du navigateur à la première visite. |
| N6 | Écoute seule | Partiel | Suricata ne bloque ni n'émet. La carte d'écoute sans adresse et sans IPv6 est une consigne d'installation, pas un contrôle du logiciel. |
| N7 | Mises à jour signées | Partiel | Règles : automatiques. Logiciel : archive signée vérifiée (testé), mais lancée à la main, pas automatique. Notre paire de clés reste à créer. |
| N8 | Redémarrage après coupure | Couvert | Reprise sans relecture ni perte après arrêt brutal. Une vraie coupure de courant n'a pas été simulée. |
| N9 | Alerte si la sonde s'arrête | Partiel | « Plus de trafic » : alerte et courriel. Machine éteinte : seulement avec le signal de vie optionnel vers un service extérieur. |
| N10 | Moins de 5 incidents par jour | Partiel | Mécanismes en place (apprentissage, regroupement, exceptions, bruit de Suricata écarté). Chiffre impossible à vérifier sans un vrai réseau. |
| N11 | Rien ne sort sans accord | Couvert | Seule sortie par défaut : le téléchargement des règles. Courriel, export et signal de vie sont désactivés par défaut. |
| N12 | Désinstallation complète | Couvert | Vérifié : aucun conteneur, volume, image ni réglage restant. Garde-fou contre la suppression d'un mauvais dossier. |
| N13 | Interface et rapport en français | Couvert | |

## Défauts trouvés par les essais réels et corrigés

Chacun a d'abord reçu un test qui le reproduit.

| Défaut | Trouvé par |
| --- | --- |
| Balayage sous-compté (12 machines au lieu de 15) car Suricata écrit les connexions dans le désordre | Vrai Suricata |
| La sonde cherchait `eve.json` alors que Suricata écrit un fichier par jour | Test d'intégration |
| Un nom de client contenant `&` ou `"` cassait le fichier de réglages | Installation réelle |
| Le conteneur Suricata redémarrait en boucle (droits sur le dossier des journaux) | Installation réelle |
| Un événement technique de Suricata présenté comme une « attaque connue » avec conseil de débrancher | Essai en direct |
| Explication qui commençait par « nouvel appareil » au lieu du signal le plus parlant | Relecture du rapport |

## À faire avant le premier client

1. Essai sur un vrai réseau avec un vrai port miroir (le nôtre, pendant deux semaines).
2. Vérifier le téléchargement des règles Emerging Threats et mesurer le bruit qu'elles produisent.
3. Créer notre paire de clés de signature et ranger la clé privée hors ligne.
4. Mesurer la mémoire et le processeur de Suricata sur ce trafic réel.
5. Faire relire les explications par une personne non technique.
6. Faire relire les modèles juridiques par un juriste.
7. Décider d'une solution pour les clients sans port miroir (F2).
