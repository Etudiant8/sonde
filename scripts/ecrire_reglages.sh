#!/bin/sh
# Écrit le fichier de réglages d'un client à partir du modèle.
#   ecrire_reglages.sh "Nom du client" modele.toml destination.toml
# Le nom est recopié tel quel, quels que soient les caractères qu'il contient.
set -eu
[ "$#" -eq 3 ] || { echo "Usage : $0 \"Nom du client\" modele.toml destination.toml" >&2; exit 2; }
# en TOML, seuls la barre oblique inverse et le guillemet doivent être protégés
nom=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
{
    printf 'nom_client = "%s"\n' "$nom"
    grep -v '^nom_client = ' "$2"
} > "$3"
