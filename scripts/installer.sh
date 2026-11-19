#!/bin/sh
# Installe Shadowreef sur la machine du client (besoin N1).
#   sudo sh scripts/installer.sh
# Installation sans question (essais, automatisation) : définir avant l'appel
#   SHADOWREEF_NOM_CLIENT, SHADOWREEF_INTERFACE, SHADOWREEF_COMPTE, SHADOWREEF_MOT_DE_PASSE
set -eu

racine="$(cd "$(dirname "$0")/.." && pwd)"
reglages="${SHADOWREEF_REGLAGES:-/etc/shadowreef}"
compose="docker compose --project-directory $racine/deploiement --env-file $reglages/shadowreef.env -f $racine/deploiement/docker-compose.yml"

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
demander SHADOWREEF_NOM_CLIENT "Nom du client" "Client"
echo "Cartes réseau de cette machine :"
ip -o link show | awk -F': ' '{print "  " $2}' | grep -v '^  lo$' || true
demander SHADOWREEF_INTERFACE "Carte reliée au port miroir du commutateur" "eth1"
ip link show "$SHADOWREEF_INTERFACE" >/dev/null 2>&1 || echouer "la carte « $SHADOWREEF_INTERFACE » n'existe pas."
demander SHADOWREEF_COMPTE "Identifiant du compte de l'interface web" "admin-client"
SHADOWREEF_PORT_WEB="${SHADOWREEF_PORT_WEB:-8443}"

dire "Fichiers de réglages dans $reglages"
mkdir -p "$reglages/tls"
chmod 750 "$reglages" "$reglages/tls"
if [ ! -f "$reglages/shadowreef.toml" ]; then
    sh "$racine/scripts/ecrire_reglages.sh" "$SHADOWREEF_NOM_CLIENT" "$racine/deploiement/shadowreef.exemple.toml" "$reglages/shadowreef.toml"
    echo "  shadowreef.toml créé"
else
    echo "  shadowreef.toml déjà présent : conservé"
fi
printf 'SHADOWREEF_INTERFACE=%s\nSHADOWREEF_REGLAGES=%s\nSHADOWREEF_PORT_WEB=%s\n' "$SHADOWREEF_INTERFACE" "$reglages" "$SHADOWREEF_PORT_WEB" > "$reglages/shadowreef.env"
if [ ! -f "$reglages/tls/shadowreef.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=shadowreef" \
        -addext "subjectAltName=DNS:shadowreef,DNS:localhost,IP:127.0.0.1" \
        -keyout "$reglages/tls/shadowreef.key" -out "$reglages/tls/shadowreef.crt" >/dev/null 2>&1
    echo "  certificat HTTPS créé (auto-signé, valable 825 jours)"
fi
# le compte de la sonde dans les conteneurs porte le numéro 10001
chown -R 0:10001 "$reglages"
chmod 640 "$reglages/shadowreef.toml" "$reglages/shadowreef.env" "$reglages/tls/shadowreef.key" "$reglages/tls/shadowreef.crt"

dire "Construction des images (quelques minutes la première fois)"
# shellcheck disable=SC2086
docker build ${SHADOWREEF_OPTIONS_BUILD:-} -q -t shadowreef-suricata:local -f "$racine/deploiement/Dockerfile.suricata" "$racine"
# shellcheck disable=SC2086
docker build ${SHADOWREEF_OPTIONS_BUILD:-} -q -t shadowreef:local -f "$racine/deploiement/Dockerfile" "$racine"

dire "Compte de l'interface web"
if [ -n "${SHADOWREEF_MOT_DE_PASSE:-}" ]; then
    $compose run --rm --no-deps -e SHADOWREEF_MOT_DE_PASSE="$SHADOWREEF_MOT_DE_PASSE" analyse creer-compte "$SHADOWREEF_COMPTE"
else
    $compose run --rm --no-deps analyse creer-compte "$SHADOWREEF_COMPTE"
fi

dire "Démarrage"
$compose up -d --no-build
adresse=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<FIN

Shadowreef est installé.
  Interface : https://${adresse:-ADRESSE-DE-CETTE-MACHINE}:$SHADOWREEF_PORT_WEB  (compte : $SHADOWREEF_COMPTE)
  Le navigateur affichera un avertissement : le certificat est auto-signé, c'est normal.
  Empreinte du certificat à vérifier lors de la première connexion :
  $(openssl x509 -in "$reglages/tls/shadowreef.crt" -noout -fingerprint -sha256 | sed 's/.*=//')
  État de la sonde : $compose exec analyse shadowreef etat
FIN
