#!/bin/sh
# Vérifie qu'une archive de mise à jour a bien été signée par l'éditeur (besoin N7).
#   verifier_version.sh cle_publique.pem sonde-X.Y.Z.tar.gz
# La signature attendue est à côté de l'archive : sonde-X.Y.Z.tar.gz.sig (Ed25519).
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage : $0 cle_publique.pem archive.tar.gz" >&2
    exit 2
fi
cle="$1"
archive="$2"
signature="$archive.sig"

for fichier in "$cle" "$archive" "$signature"; do
    if [ ! -s "$fichier" ]; then
        echo "REFUS : fichier absent ou vide : $fichier" >&2
        exit 1
    fi
done

if openssl pkeyutl -verify -pubin -inkey "$cle" -rawin -in "$archive" -sigfile "$signature" >/dev/null 2>&1; then
    echo "Signature valide : $archive"
else
    echo "REFUS : la signature ne correspond pas. L'archive a été modifiée ou ne vient pas de l'éditeur." >&2
    exit 1
fi
