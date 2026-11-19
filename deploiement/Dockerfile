# Image de Shadowreef : analyse, interface web, rapport.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates tzdata fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Compte sans privilège : la sonde ne tourne jamais en administrateur
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin shadowreef \
 && mkdir -p /var/lib/shadowreef /etc/shadowreef && chown shadowreef:shadowreef /var/lib/shadowreef

COPY pyproject.toml /src/
COPY shadowreef /src/shadowreef
# Derrière un proxy d'entreprise qui inspecte le HTTPS, fournir son certificat d'autorité :
#   docker build --secret id=ca_entreprise,src=/chemin/ca.crt ...
RUN --mount=type=secret,id=ca_entreprise,required=false \
    if [ -s /run/secrets/ca_entreprise ]; then export PIP_CERT=/run/secrets/ca_entreprise; fi \
 && python3 -m venv /opt/shadowreef \
 && /opt/shadowreef/bin/pip install --no-cache-dir /src \
 && rm -rf /src

ENV PATH="/opt/shadowreef/bin:$PATH" SHADOWREEF_CONFIG=/etc/shadowreef/shadowreef.toml PYTHONUNBUFFERED=1
USER shadowreef
WORKDIR /var/lib/shadowreef
ENTRYPOINT ["shadowreef"]
CMD ["surveiller"]
