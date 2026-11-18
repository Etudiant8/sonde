#!/bin/sh
# Installe la sonde sur la machine du client (besoin N1).
#   sudo sh scripts/installer.sh
# Installation sans question (essais, automatisation) : définir avant l'appel
#   SONDE_NOM_CLIENT, SONDE_INTERFACE, SONDE_COMPTE, SONDE_MOT_DE_PASSE
set -eu

racine="$(cd "$(dirname "$0")/.." && pwd)"
reglages="${SONDE_REGLAGES:-/etc/sonde}"
compose="docker compose --project-directory $racine/deploiement --env-file $reglages/sonde.env -f $racine/deploiement/docker-compose.yml"

dire() { printf '\n== %s\n' "$1"; }
echouer() { printf 'Erreur : %s\n' "$1" >&2; exit 1; }
demander() {  # demander VARIABLE "question" "défaut"
    eval "valeur=\${$1:-}"
    if [ -z "$valeur" ]; then
        printf '%s [%s] : ' "$2" "$3"
        read -r valeur
        [ -n "$valeur" ] || valeur="$3"
    fi
    eval "$1=\$valeur"
}

[ "$(id -u)" -eq 0 ] || echouer "lancez ce script en administrateur (sudo)."
command -v docker >/dev/null 2>&1 || echouer "Docker n'est pas installé (https://docs.docker.com/engine/install/)."
docker compose version >/dev/null 2>&1 || echouer "le module « docker compose » est absent."
command -v openssl >/dev/null 2>&1 || echouer "openssl n'est pas installé."

dire "Réglages"
demander SONDE_NOM_CLIENT "Nom du client" "Client"
echo "Cartes réseau de cette machine :"
ip -o link show | awk -F': ' '{print "  " $2}' | grep -v '^  lo$' || true
demander SONDE_INTERFACE "Carte reliée au port miroir du commutateur" "eth1"
ip link show "$SONDE_INTERFACE" >/dev/null 2>&1 || echouer "la carte « $SONDE_INTERFACE » n'existe pas."
demander SONDE_COMPTE "Identifiant du compte de l'interface web" "admin-client"
SONDE_PORT_WEB="${SONDE_PORT_WEB:-8443}"

dire "Fichiers de réglages dans $reglages"
mkdir -p "$reglages/tls"
chmod 750 "$reglages" "$reglages/tls"
if [ ! -f "$reglages/sonde.toml" ]; then
    sh "$racine/scripts/ecrire_reglages.sh" "$SONDE_NOM_CLIENT" "$racine/deploiement/sonde.exemple.toml" "$reglages/sonde.toml"
    echo "  sonde.toml créé"
else
    echo "  sonde.toml déjà présent : conservé"
fi
printf 'SONDE_INTERFACE=%s\nSONDE_REGLAGES=%s\nSONDE_PORT_WEB=%s\n' "$SONDE_INTERFACE" "$reglages" "$SONDE_PORT_WEB" > "$reglages/sonde.env"
if [ ! -f "$reglages/tls/sonde.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=sonde" \
        -addext "subjectAltName=DNS:sonde,DNS:localhost,IP:127.0.0.1" \
        -keyout "$reglages/tls/sonde.key" -out "$reglages/tls/sonde.crt" >/dev/null 2>&1
    echo "  certificat HTTPS créé (auto-signé, valable 825 jours)"
fi
# le compte de la sonde dans les conteneurs porte le numéro 10001
chown -R 0:10001 "$reglages"
chmod 640 "$reglages/sonde.toml" "$reglages/sonde.env" "$reglages/tls/sonde.key" "$reglages/tls/sonde.crt"

dire "Construction des images (quelques minutes la première fois)"
# shellcheck disable=SC2086
docker build ${SONDE_OPTIONS_BUILD:-} -q -t sonde-suricata:local -f "$racine/deploiement/Dockerfile.suricata" "$racine"
# shellcheck disable=SC2086
docker build ${SONDE_OPTIONS_BUILD:-} -q -t sonde:local -f "$racine/deploiement/Dockerfile" "$racine"

dire "Compte de l'interface web"
if [ -n "${SONDE_MOT_DE_PASSE:-}" ]; then
    $compose run --rm --no-deps -e SONDE_MOT_DE_PASSE="$SONDE_MOT_DE_PASSE" sonde creer-compte "$SONDE_COMPTE"
else
    $compose run --rm --no-deps sonde creer-compte "$SONDE_COMPTE"
fi

dire "Démarrage"
$compose up -d --no-build
adresse=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<FIN

Sonde installée.
  Interface : https://${adresse:-ADRESSE-DE-CETTE-MACHINE}:$SONDE_PORT_WEB  (compte : $SONDE_COMPTE)
  Le navigateur affichera un avertissement : le certificat est auto-signé, c'est normal.
  Empreinte du certificat à vérifier lors de la première connexion :
  $(openssl x509 -in "$reglages/tls/sonde.crt" -noout -fingerprint -sha256 | sed 's/.*=//')
  État de la sonde : $compose exec sonde sonde etat
FIN
