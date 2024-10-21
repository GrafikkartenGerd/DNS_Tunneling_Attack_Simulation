import socket
from time import sleep
import dns.message
import dns.query


def send_dns_request(server_ip, domain):
    # Erstelle eine DNS-Anfrage
    request = dns.message.make_query(domain, dns.rdatatype.A)
    request_bytes = request.to_wire()

    # Sende die Anfrage und empfange die Antwort
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)  # Setze einen Timeout für das Warten auf die Antwort
        sock.sendto(request_bytes, (server_ip, 12345))
        print(f"DNS request sent to {server_ip} for domain {domain}")

        try:
            # Empfange die Antwort
            response_bytes, addr = sock.recvfrom(512)  # DNS-Antworten sind in der Regel maximal 512 Bytes
            response = dns.message.from_wire(response_bytes)  # Konvertiere die Antwort in ein lesbares DNS-Format
            print(f"Received DNS response from {addr}:\n{response}")
        except socket.timeout:
            print("No response received (Timeout)")

def send_minimal_dns_request(server_ip, domain,port):
    # Erstelle eine minimale DNS-Anfrage mit einem Dummy-Domainnamen
    request = dns.message.make_query(domain, dns.rdatatype.A)  # Dummy-Anfrage
    request_bytes = request.to_wire()  # Umwandeln in Bytes

    # Sende die Anfrage an den Empfänger
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request_bytes, (server_ip, port))
        print(f"Minimal DNS request sent to {server_ip}:{port}")

if __name__ == "__main__":
    receiver_ip = "172.36.0.3"  # Ändere dies in die IP des Empfängers, falls notwendig
    domain_name = "justus-sieger.de"
    for i in range(100):
        sleep(5)
        print(f"Sending DNS request {i + 1}/100")  # Zähle die Anfragen mit
        send_minimal_dns_request(receiver_ip, domain_name, 12345)
