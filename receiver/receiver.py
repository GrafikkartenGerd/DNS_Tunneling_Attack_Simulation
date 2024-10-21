import socket
import dns.message
import dns.rrset
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.TXT


def start_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', port))
        print(f"Listening for DNS requests on port {port}...")

        while True:
            data, addr = sock.recvfrom(512)
            print(f"Received DNS request from {addr}")

            try:
                request = dns.message.from_wire(data)

                domain = request.question[0].name
                data = domain.split('.')[0]

                if request.additional:
                    additional_records = []
                    for additional in request.additional:
                        if additional.rdtype == dns.rdatatype.TXT:
                            for txt in additional.items:
                                additional_records.append(b''.join(txt.strings).decode())

                    if additional_records:
                        print(f"Custom data received in Additional Section: {additional_records}")
                    else:
                        print("No valid TXT data in Additional Section.")
                else:
                    print("No Additional Section found in the request.")

                # Erstelle eine Antwort auf die Anfrage
                response = dns.message.make_response(request)

                # Name und TTL für die Antwort setzen
                name = request.question[0].name
                ttl = 300

                # TXT-Record für die Antwort hinzufügen
                rdata = dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, ["ja da bin ich"])
                rrset = dns.rrset.from_rdata(name, ttl, rdata)
                response.answer.append(rrset)

                # Sende die Antwort an den Client
                sock.sendto(response.to_wire(), addr)
                print(f"Sent TXT response 'ja da bin ich' to {addr}")

            except Exception as e:
                print(f"Error processing request: {e}")


if __name__ == "__main__":
    port = 12345
    start_server(port)
