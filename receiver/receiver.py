import base64
import hashlib
import socket
import dns.message
import dns.rrset
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.TXT

def dns_decompose(text):
    print(text)

    padding_needed = len(text) % 4
    if padding_needed:
        text += '=' * (4 - padding_needed)

    try:
        decoded_bytes = base64.b64decode(text)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error decoding: {e}")
        return None

def hash_string(input_string):
    # Erstelle ein SHA-256 Hash-Objekt
    sha256_hash = hashlib.sha256()

    # Füge den String dem Hash-Objekt hinzu (muss zuerst in Bytes umgewandelt werden)
    sha256_hash.update(input_string.encode('utf-8'))

    # Gib den Hash als hexadezimale Darstellung zurück
    return sha256_hash.hexdigest()

def start_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', port))
        print(f"Listening for DNS requests on port {port}...")

        all_content = ""
        while True:
            data, addr = sock.recvfrom(512)
            print(f"Received DNS request from {addr}")

            try:
                request = dns.message.from_wire(data)

                domain = str(request.question[0].name)
                data = domain.split('.')[0]
                MyHash = hash_string(domain)

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
                    if additional_records[0] == MyHash:
                        print("Received hash matches the domain hash.")
                        print("++++++" + dns_decompose(data) + "++++++")
                        all_content += dns_decompose(data)

                        if domain.split('.')[1] == 0:
                            print("End of transmission")
                            print(all_content)
                            all_content = ""

                        message = ["False"]

                    else:
                        print("Received hash does not match the domain hash.")
                        message = ["True"]
                else:
                    print("No Additional Section found in the request.")
                    message = ["True"]

                # Erstelle eine Antwort auf die Anfrage
                response = dns.message.make_response(request)

                # Name und TTL für die Antwort setzen
                name = request.question[0].name
                ttl = 300

                # TXT-Record für die Antwort hinzufügen
                rdata = dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, message)
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
