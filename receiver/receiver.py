import socket
import dns.message
import dns.resolver

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
                # Hier können wir einfach die Anfrage drucken, um sicherzustellen, dass sie empfangen wird

                # Führe eine DNS-Abfrage durch
                answers = dns.resolver.resolve(request.question[0].name, request.question[0].rdtype)
                response = dns.message.make_response(request)

                # Füge die Antwort hinzu
                for rdata in answers:
                    response.answer.append(dns.rrset.from_rdata(request.question[0].name, 300, rdata))

                # Sende die Antwort zurück
                sock.sendto(response.to_wire(), addr)
                print(f"Sent response to {addr}")
            except Exception as e:
                print(f"Error processing request: {e}")

if __name__ == "__main__":
    port = 12345
    start_server(port)
