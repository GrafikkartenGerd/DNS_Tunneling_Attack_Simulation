import socket
import dns.message
import dns.rrset
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.TXT  # Importiere den richtigen TXT-Record-Typ


def start_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', port))
        print(f"Listening for DNS requests on port {port}...")

        while True:
            # Empfange die Anfrage
            data, addr = sock.recvfrom(512)  # DNS-Pakete haben eine maximale Größe von 512 Bytes
            print(f"Received DNS request from {addr}")

            # Verarbeite die Anfrage
            try:
                request = dns.message.from_wire(data)
                print(f"Request: {request}")

                # Erstelle eine manuelle Antwort mit einem TXT-Record
                response = dns.message.make_response(request)

                # Füge eine TXT-Antwort hinzu
                name = request.question[0].name
                ttl = 300
                rdata = dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, ["ja da bin ich"])

                # Erstelle einen Resource Record Set (RRSet) und füge ihn der Antwort hinzu
                rrset = dns.rrset.from_rdata(name, ttl, rdata)
                response.answer.append(rrset)

                # Sende die manipulierte Antwort zurück
                sock.sendto(response.to_wire(), addr)
                print(f"Sent TXT response 'ja da bin ich' to {addr}")
            except Exception as e:
                print(f"Error processing request: {e}")

if __name__ == "__main__":
    port = 12345
    start_server(port)
