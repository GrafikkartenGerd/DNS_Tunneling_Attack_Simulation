import socket
from time import sleep

import dns.message
import dns.query


def send_dns_request(server_ip, domain):
    # Erstelle eine DNS-Anfrage
    request = dns.message.make_query(domain, dns.rdatatype.A)
    request_bytes = request.to_wire()

    # Sende die Anfrage an den Empfänger
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request_bytes, (server_ip, 12345))
        print(f"DNS request sent to {server_ip} for domain {domain}")


if __name__ == "__main__":
    receiver_ip = "127.0.0.1"  # Ändere dies in die IP des Empfängers, falls notwendig
    #receiver_ip = "172.36.0.3"  # Ändere dies in die IP des Empfängers, falls notwendig
    domain_name = "justus-sieger.de"
for i in range(100):
    sleep(5)
    print(f"Sending DNS request {i+1}/100")  # Zähle die Anfragen mit
    send_dns_request(receiver_ip, domain_name)
