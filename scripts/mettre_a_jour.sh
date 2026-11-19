#!/bin/sh
# Met à jour la sonde à partir d'une archive signée par l'éditeur (besoin N7).
#   sudo sh scripts/mettre_a_jour.sh /chemin/shadowreef-X.Y.Z.tar.gz
# La clé publique de l'éditeur est dans scripts/cle_publique.pem ; la signature
# (.sig) doit être à côté de l'archive. Une archive non signée est refusée.
set -eu

racine="$(cd "$(dirname "$0")/.." && pwd)"
reglages="${SHADOWREEF_REGLAGES:-/etc/shadowreef}"
cle="${SHADOWREEF_CLE_PUBLIQUE:-$racine/scripts/cle_publique.pem}"

[ "$#" -eq 1 ] || { echo "Usage : $0 shadowreef-X.Y.Z.tar.gz" >&2; exit 2; }
archive="$1"
[ "$(id -u)" -eq 0 ] || { echo "Erreur : lancez ce script en administrateur (sudo)." >&2; exit 1; }

sh "$racine/scripts/verifier_version.sh" "$cle" "$archive"

travail=$(mktemp -d)
trap 'rm -rf "$travail"' EXIT
tar -xzf "$archive" -C "$travail"
source_maj=$(find "$travail" -maxdepth 2 -name pyproject.toml -exec dirname {} \; | head -n 1)
[ -n "$source_maj" ] || { echo "Erreur : l'archive ne contient pas la sonde." >&2; exit 1; }

# shellcheck disable=SC2086
docker build ${SHADOWREEF_OPTIONS_BUILD:-} -q -t shadowreef-suricata:local -f "$source_maj/deploiement/Dockerfile.suricata" "$source_maj"
# shellcheck disable=SC2086
docker build ${SHADOWREEF_OPTIONS_BUILD:-} -q -t shadowreef:local -f "$source_maj/deploiement/Dockerfile" "$source_maj"
cp "$source_maj/deploiement/docker-compose.yml" "$racine/deploiement/docker-compose.yml"
docker compose --project-directory "$racine/deploiement" --env-file "$reglages/shadowreef.env" \
    -f "$racine/deploiement/docker-compose.yml" up -d --no-build
echo "Mise à jour terminée. Les données et les réglages du client sont conservés."
