#!/bin/sh
# Démarre Suricata en écoute seule (N6) et tient les règles de détection à jour (N7).
set -eu

: "${SHADOWREEF_INTERFACE:?Indiquez la carte reliée au port miroir (SHADOWREEF_INTERFACE)}"

# La sonde (compte 10001) doit pouvoir lire et purger les journaux
mkdir -p /var/log/suricata /var/lib/suricata/rules
chown 10001 /var/log/suricata

# Règles de détection : premier téléchargement, puis une mise à jour par jour.
# Sans accès à Internet, Suricata démarre quand même et journalise l'activité du réseau.
if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    suricata-update --no-test --no-reload || echo "Règles non téléchargées (pas d'accès à Internet ?) : nouvel essai dans 1 h."
fi
(
    while true; do
        if [ -s /var/lib/suricata/rules/suricata.rules ]; then sleep 86400; else sleep 3600; fi
        suricata-update --no-test --no-reload && suricatasc -c reload-rules >/dev/null 2>&1 || true
    done
) &

# Écoute de tout le trafic copié par le commutateur ; la carte n'émet rien
ip link set "$SHADOWREEF_INTERFACE" up promisc on || echo "Impossible d'activer le mode écoute sur $SHADOWREEF_INTERFACE"

exec suricata -c /etc/suricata/suricata.yaml -i "$SHADOWREEF_INTERFACE" -k none "$@"
