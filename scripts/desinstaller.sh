#!/bin/sh
# Retire complètement la sonde et toutes les données enregistrées chez le client (besoin N12).
#   sudo sh scripts/desinstaller.sh          (demande confirmation)
#   sudo sh scripts/desinstaller.sh --oui    (sans question)
set -eu

racine="$(cd "$(dirname "$0")/.." && pwd)"
reglages="${SONDE_REGLAGES:-/etc/sonde}"

[ "$(id -u)" -eq 0 ] || { echo "Erreur : lancez ce script en administrateur (sudo)." >&2; exit 1; }
# Garde-fou : on ne supprime qu'un dossier de réglages créé par l'installateur de la sonde
case "$reglages" in
    ""|"/"|"/etc"|"/home"|"/root"|"/usr"|"/var") echo "Erreur : dossier de réglages refusé : « $reglages »." >&2; exit 1 ;;
esac
if [ -d "$reglages" ] && [ ! -f "$reglages/sonde.env" ]; then
    echo "Erreur : $reglages n'est pas un dossier de réglages de la sonde (sonde.env absent). Rien n'a été supprimé." >&2
    exit 1
fi
if [ "${1:-}" != "--oui" ]; then
    printf 'Supprimer la sonde, ses réglages et TOUTES ses données ? Tapez "supprimer" pour confirmer : '
    read -r reponse
    [ "$reponse" = "supprimer" ] || { echo "Abandon : rien n'a été supprimé."; exit 1; }
fi

fichier_env="$reglages/sonde.env"
[ -f "$fichier_env" ] || { fichier_env=$(mktemp); printf 'SONDE_INTERFACE=lo\nSONDE_REGLAGES=%s\n' "$reglages" > "$fichier_env"; }
docker compose --project-directory "$racine/deploiement" --env-file "$fichier_env" \
    -f "$racine/deploiement/docker-compose.yml" down --volumes --remove-orphans 2>&1 || true
docker image rm sonde:local sonde-suricata:local >/dev/null 2>&1 || true
rm -rf "$reglages"
echo "Sonde désinstallée : conteneurs, données, journaux et réglages supprimés."
