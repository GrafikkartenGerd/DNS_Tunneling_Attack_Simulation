import base64
import hashlib
import socket
import dns.message
import dns.rrset
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.TXT
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

# Decompose the base64 encoded text
def dns_decompose(text):
    print(text)

    # Add padding if needed
    padding_needed = len(text) % 4
    if padding_needed:
        text += '=' * (4 - padding_needed)
    try:
        # Decode the base64 encoded text
        decoded_bytes = base64.b64decode(text)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        # Handle decoding errors
        print(f"Error decoding: {e}")
        return None

# Write the received packets to a pcap file
def pcap_writer():
    # Sniff packets on the eth0 interface and write them to a pcap file
    def sniff_and_write():
        packets = sniff(iface="eth0", filter="udp and port 53", timeout=8)
        wrpcap("receiv_data.pcap", packets)
        # Write the packet details to a text file
        with open("packet_details.txt", "w") as file:
            for packet in packets:
                file.write(packet.show(dump=True) + "\n")
    # Start the sniffing and writing thread
    thread = threading.Thread(target=sniff_and_write)
    thread.start()

# Hash the input string using SHA-256
def hash_string(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# Start the DNS server on the specified port
def start_server(port):
    pcap_writer()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', port))
        print(f"Listening for DNS requests on port {port}...")

        all_content = ""
        receiving = True
        while receiving:
            data, addr = sock.recvfrom(512)
            print(f"Received DNS request from {addr}")
            try:
                # Parse the DNS request
                request = dns.message.from_wire(data)

                domain = str(request.question[0].name)
                data = domain.split('.')[0]
                my_hash = hash_string(domain)

                # Check if the request contains an Additional Section
                if request.additional:
                    additional_records = []
                    for additional in request.additional:
                        # Check if the Additional Section contains TXT records
                        if additional.rdtype == dns.rdatatype.TXT:
                            for txt in additional.items:
                                # Decode the TXT record and add it to the list
                                additional_records.append(b''.join(txt.strings).decode())

                    if not additional_records:
                        print("No hash for validation found in the Additional Section.")
                    if additional_records[0] == my_hash:
                        # Extract the data from the request
                        all_content += dns_decompose(data)
                        # Write the data to a file
                        with open("secret_file.txt", "w") as secret_file:
                            secret_file.write(all_content)
                        # Check if the domain is the end of transmission
                        if domain.split('.')[1] == "0":
                            print("End of transmission")
                            print(all_content)
                            all_content = ""
                            receiving = False

                        message = ["False"]
                    else:
                        # The hash in the Additional Section does not match the domain hash
                        print(f"Received hash from package {domain.split('.')[1]} does not match the domain hash.")
                        message = ["True"]
                else:
                    print("No Additional Section found in the request.")
                    message = ["True"]
                # Create a DNS response with the message
                response = dns.message.make_response(request)

                # Add the TXT record to the response
                name = request.question[0].name
                ttl = 300
                rdata = dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, message)
                rrset = dns.rrset.from_rdata(name, ttl, rdata)
                response.answer.append(rrset)

                # Send the response back to the client
                sock.sendto(response.to_wire(), addr)

            except Exception as e:
                print(f"Error processing request: {e}")


if __name__ == "__main__":
    port = 53
    start_server(port)
