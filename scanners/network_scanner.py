from scapy.all import ARP, Ether, srp
import socket


def scan_network(network):

    try:

        arp = ARP(pdst=network)

        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        packet = ether / arp

        result = srp(
            packet,
            timeout=3,
            verbose=False
        )[0]

        devices = []

        for sent, received in result:

            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                hostname = "Unknown"

            devices.append({

                "ip": received.psrc,

                "mac": received.hwsrc,

                "hostname": hostname

            })

        return devices

    except Exception as e:

        return [{
            "ip": "Error",
            "mac": str(e),
            "hostname": "-"
        }]