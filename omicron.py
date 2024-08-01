import os
import smtplib
import ssl
from email.message import EmailMessage
import geoip2.database
import scapy.all as scapy

# GeoIP2 DB
reader = geoip2.database.Reader('/usr/share/GeoIP/GeoIP.dat')
suspicious_countries = ['RU', 'CN', 'MM', 'KP', 'IR', 'SY', 'VE', 'BY']

#The list is to be checked and modified. 
#The list contains: 
#Russia, China (PRC), Myanmar, North Korea, Iran, Syria, Venezuela, Belarus.
#SUGGESTION: Addition of: Brazil, any Sub-Saharian country that is not South-Africa, except some that are more active on the Internet lawfully
#Addition of the Entire Middle East (excl. IL due to regular normal traffic, else it would have been on the list).
#Addition of Pakistan, Nepal, and surrounding countries
#Addition of the Phillippines, though as a special suspicious country due to regular normal traffic, but also presence of hackers in this country, 
#so maybe only after a certain amount of packet / amount of time with X or Y device conversing with a Phillipines-based IP, will it activate OMICRON.
#Addition of Proxies list, that will be updated as long as there are new proxies; if a packet goes through a proxy, IMO it is worth checking it.

# Client information, to be tailored to each client before proceeding with the selling
def client(client_info):
    return f"Client Info: {client_info}"

def analyze_packet(packet):
    dest_ip = packet['dest_ip']
    response = reader.city(dest_ip)
    country_code = response.country.iso_code
    if country_code in suspicious_countries:
        send_alert(packet)

def send_alert(packet):
    encrypted_packet = encrypt_packet(packet)
    send_email(encrypted_packet)

def encrypt_packet(packet):
    return str(packet)

def send_email(packet):
    port = 465
    smtp_server = "IDS SMTP SERVER"
    sender_email = #IDS EMAIL ADDRESS FOR SENDING IT FROM [CLASSIFIED] PRODUCTS.
    receiver_email = #IDS EMAIL ADDRESS TO RECEIVE THE MAILS FROM [CLASSIFIED] PRODUCTS.
    password = #pwd to be changed regularly

    message = EmailMessage()
    message.set_content(f"Encrypted Packet Data:\n{packet}")

    #MSG writing and sending
  
    message["Subject"] = "Packet Alert from an IDS CLASSIFIED ITEM"
    message["From"] = sender_email
    message["To"] = receiver_email

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.send_message(message)

def capture_packets():
    packets = scapy.sniff(count=10)
    return [{"dest_ip": packet[scapy.IP].dst} for packet in packets if packet.haslayer(scapy.IP)]

# Main loop for packet analysis
for packet in capture_packets():
    analyze_packet(packet)
