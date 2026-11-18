# Image de la sonde : analyse, interface web, rapport.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates tzdata fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Compte sans privilège : la sonde ne tourne jamais en administrateur
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin sonde \
 && mkdir -p /var/lib/sonde /etc/sonde && chown sonde:sonde /var/lib/sonde

COPY pyproject.toml /src/
COPY sonde /src/sonde
# Derrière un proxy d'entreprise qui inspecte le HTTPS, fournir son certificat d'autorité :
#   docker build --secret id=ca_entreprise,src=/chemin/ca.crt ...
RUN --mount=type=secret,id=ca_entreprise,required=false \
    if [ -s /run/secrets/ca_entreprise ]; then export PIP_CERT=/run/secrets/ca_entreprise; fi \
 && python3 -m venv /opt/sonde \
 && /opt/sonde/bin/pip install --no-cache-dir /src \
 && rm -rf /src

ENV PATH="/opt/sonde/bin:$PATH" SONDE_CONFIG=/etc/sonde/sonde.toml PYTHONUNBUFFERED=1
USER sonde
WORKDIR /var/lib/sonde
ENTRYPOINT ["sonde"]
CMD ["surveiller"]
