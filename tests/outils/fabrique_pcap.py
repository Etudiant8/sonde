"""Fabrique une capture réseau synthétique pour les tests d'intégration.

Le scénario simule un petit réseau d'entreprise (192.168.1.0/24) avec du
trafic normal et plusieurs comportements que la sonde doit repérer.
"""
from __future__ import annotations

import sys

from scapy.all import BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

PASSERELLE = ("192.168.1.1", "aa:aa:aa:00:00:01")
PC_COMPTA = ("192.168.1.10", "00:11:22:33:44:10")
SERVEUR = ("192.168.1.20", "00:11:22:33:44:20")
NAS = ("192.168.1.30", "00:11:22:33:44:30")
INTRUS = ("192.168.1.66", "de:ad:be:ef:00:66")

T0 = 1_780_000_000.0  # horodatage de départ (UTC)


class Capture:
    def __init__(self) -> None:
        self.paquets = []
        self.t = T0

    def ajoute(self, paquet, pas: float = 0.01) -> None:
        self.t += pas
        paquet.time = self.t
        self.paquets.append(paquet)

    def avance(self, secondes: float) -> None:
        self.t += secondes

    def mac_de(self, ip: str) -> str:
        for hote in (PASSERELLE, PC_COMPTA, SERVEUR, NAS, INTRUS):
            if hote[0] == ip:
                return hote[1]
        if ip.startswith("192.168.1."):
            return "00:11:22:33:55:%02x" % int(ip.split(".")[-1])
        return PASSERELLE[1]  # tout ce qui vient d'Internet passe par la passerelle

    def trame(self, src: str, dst: str):
        return Ether(src=self.mac_de(src), dst=self.mac_de(dst)) / IP(src=src, dst=dst)

    def session_tcp(self, client: str, serveur: str, port: int, envoi: bytes = b"",
                    reponse: bytes = b"", sport: int = 40000, morceau: int = 1400) -> None:
        """Session TCP complète : poignée de main, données, fermeture."""
        sc, ss = 1000, 5000
        self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="S", seq=sc))
        self.ajoute(self.trame(serveur, client) / TCP(sport=port, dport=sport, flags="SA", seq=ss, ack=sc + 1))
        sc += 1
        ss += 1
        self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="A", seq=sc, ack=ss))
        for i in range(0, len(envoi), morceau):
            bloc = envoi[i:i + morceau]
            self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="PA", seq=sc, ack=ss) / Raw(bloc), 0.001)
            sc += len(bloc)
            self.ajoute(self.trame(serveur, client) / TCP(sport=port, dport=sport, flags="A", seq=ss, ack=sc), 0.001)
        for i in range(0, len(reponse), morceau):
            bloc = reponse[i:i + morceau]
            self.ajoute(self.trame(serveur, client) / TCP(sport=port, dport=sport, flags="PA", seq=ss, ack=sc) / Raw(bloc), 0.001)
            ss += len(bloc)
            self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="A", seq=sc, ack=ss), 0.001)
        self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="FA", seq=sc, ack=ss))
        self.ajoute(self.trame(serveur, client) / TCP(sport=port, dport=sport, flags="FA", seq=ss, ack=sc + 1))
        self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="A", seq=sc + 1, ack=ss + 1))

    def syn_refuse(self, client: str, serveur: str, port: int, sport: int) -> None:
        self.ajoute(self.trame(client, serveur) / TCP(sport=sport, dport=port, flags="S", seq=1))
        self.ajoute(self.trame(serveur, client) / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=2))


def scenario() -> Capture:
    c = Capture()

    # 1. Le PC de la comptabilité demande une adresse (DHCP) : on apprend son nom.
    mac_brute = bytes.fromhex(PC_COMPTA[1].replace(":", ""))
    c.ajoute(Ether(src=PC_COMPTA[1], dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
             / UDP(sport=68, dport=67) / BOOTP(chaddr=mac_brute, xid=0x1234)
             / DHCP(options=[("message-type", "request"), ("hostname", "PC-COMPTA"),
                             ("requested_addr", PC_COMPTA[0]), "end"]))
    c.ajoute(Ether(src=PASSERELLE[1], dst=PC_COMPTA[1]) / IP(src=PASSERELLE[0], dst=PC_COMPTA[0])
             / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=PC_COMPTA[0], chaddr=mac_brute, xid=0x1234)
             / DHCP(options=[("message-type", "ack"), ("lease_time", 86400), "end"]))

    # 2. Navigation normale : requête DNS puis connexion chiffrée.
    c.ajoute(c.trame(PC_COMPTA[0], PASSERELLE[0]) / UDP(sport=5353, dport=53)
             / DNS(id=7, rd=1, qd=DNSQR(qname="www.example.re")))
    c.ajoute(c.trame(PASSERELLE[0], PC_COMPTA[0]) / UDP(sport=53, dport=5353)
             / DNS(id=7, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.re"),
                   an=DNSRR(rrname="www.example.re", ttl=300, rdata="203.0.113.10")))
    c.session_tcp(PC_COMPTA[0], "203.0.113.10", 443, envoi=b"\x16\x03\x01" + b"x" * 300,
                  reponse=b"y" * 3000, sport=40001)

    # 3. Protocole non chiffré : Telnet vers le serveur interne.
    c.session_tcp(PC_COMPTA[0], SERVEUR[0], 23, envoi=b"admin\r\nmotdepasse\r\n",
                  reponse=b"login: Password: $ ", sport=40002)

    # 4. Réponse d'attaque connue (déclenche une règle de signature).
    c.session_tcp(PC_COMPTA[0], "203.0.113.66", 80,
                  envoi=b"GET /shell.php?cmd=id HTTP/1.1\r\nHost: mauvais.example\r\n\r\n",
                  reponse=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 39\r\n\r\n"
                          b"uid=0(root) gid=0(root) groups=0(root)\n", sport=40003)

    # 5. Balayage interne : l'intrus essaie le port 445 sur 15 machines.
    c.avance(5)
    for i in range(15):
        c.syn_refuse(INTRUS[0], "192.168.1.%d" % (100 + i), 445, sport=50000 + i)

    # 6. Service exposé : une machine d'Internet ouvre le bureau à distance du serveur.
    c.avance(5)
    c.session_tcp("198.51.100.7", SERVEUR[0], 3389, envoi=b"\x03\x00\x00\x13" + b"z" * 50,
                  reponse=b"\x03\x00\x00\x13" + b"z" * 50, sport=40004)

    # 7. Gros envoi vers l'extérieur depuis le NAS (2 Mo).
    c.avance(5)
    c.session_tcp(NAS[0], "203.0.113.99", 443, envoi=b"D" * 2_000_000, reponse=b"ok", sport=40005)
    return c


if __name__ == "__main__":
    sortie = sys.argv[1] if len(sys.argv) > 1 else "scenario.pcap"
    capture = scenario()
    wrpcap(sortie, capture.paquets)
    print(f"{len(capture.paquets)} paquets écrits dans {sortie}")
