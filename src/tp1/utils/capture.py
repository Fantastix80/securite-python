import time
from collections import Counter, defaultdict
from scapy.all import sniff
from scapy.plist import PacketList, Packet
from scapy.layers.l2 import ARP
from src.tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.packets = PacketList()
        self.summary = ""
        self.protocol_counts = Counter()
        self.observed_arp_table = {}
        self.arp_activity = defaultdict(list)
        self.alerts = [
            {"type": "type test", "message": "Voici mon message de test !"},
            {
                "type": "ATTAQUE DETECTEE",
                "message": "UNE ENORME ATTAQUE NOUS A TOUCHEE ON EST DANS LA MOUISE !",
            },
        ]

    def process_packets(self, packet: Packet) -> None:
        """
        Analyse each packet in real time
        """
        self.detect_injection_SQL(packet)
        self.detect_ARP_spoofing(packet)

    def capture_trafic(self) -> None:
        """
        Capture network trafic
        """
        self.packets = sniff(prn=self.process_packets)

    def sort_network_protocols(self) -> None:
        """
        Sort and return all captured network protocols
        """
        sorted_protocols = sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True)
        self.protocol_counts = sorted_protocols

    def get_all_protocols(self) -> None:
        """
        Return all protocols captured with total packets number
        """
        for packet in self.packets:
            for layer in packet.layers():
                layer_name = layer.__name__
                self.protocol_counts[layer_name] += 1

    def detect_injection_SQL(self, packet: Packet) -> None:
        """
        Detect SQL injection
        """

        if packet.haslayer("TCP") and packet.haslayer("Raw"):
            sport = packet["TCP"].sport
            dport = packet["TCP"].dport

            if sport == 80 or dport == 80:
                payload = packet["Raw"].load.decode(errors="ignore")
                if "'" in payload and ("or" in payload or "OR" in payload) and ";" in payload:
                    logger.warn(f"SQL Injection détectée: {payload}")
                    self.alerts.append(
                        {"type": "SQL Injection", "message": f"SQL Injection detected: {payload}"}
                    )
                    # TODO: take action

    def detect_ARP_spoofing(self, packet: Packet) -> None:
        """
        Detect ARP spoofing + flood detection
        """

        if ARP in packet and packet[ARP].op == 2:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            now = time.time()

            if ip in self.observed_arp_table:
                if self.observed_arp_table[ip] != mac:
                    logger.warn(
                        f"ARP spoofing détecté: {ip} anciennement associé à {self.observed_arp_table[ip]} et maintenant {mac}"
                    )
                    self.alerts.append(
                        {
                            "type": "ARP Spoofing",
                            "message": f"ARP spoofing détecté: {ip} anciennement associé à {self.observed_arp_table[ip]} et maintenant {mac}",
                        }
                    )
                    # TODO: block the machine
            else:
                self.observed_arp_table[ip] = mac

            self.arp_activity[ip].append(now)
            self.arp_activity[ip] = [ts for ts in self.arp_activity[ip] if now - ts < 5]

            if len(self.arp_activity[ip]) > 5:
                logger.warning(
                    f"Activité ARP anormale: plus de 5 réponses envoyées par {ip} en moins de 5 secondes"
                )
                self.alerts.append(
                    {
                        "type": "ARP Flood",
                        "message": f"ARP flood détecté: plus de 5 réponses envoyées par {ip} en moins de 5 secondes",
                    }
                )
                # TODO: block the machine

    def analyse(self) -> None:
        """
        Analyse all captured data and return statement
        """

        self.get_all_protocols()
        self.sort_network_protocols()
        self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> None:
        """
        Generate summary
        """
        protocol_count = len(self.protocol_counts)
        packet_count = 0
        for protocol, count in self.protocol_counts:
            packet_count += count

        self.summary = f"Durant cette analyse réseau, nous avons capturés {packet_count} packets provenant de {protocol_count} protocoles différents. Au cours de cette analyse, {len(self.alerts)} attaques ont pu être évitées grâce à ce programme."
