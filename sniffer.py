from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
from datetime import datetime

captured_packets = []

is_capturing = False

ip_to_website = {}


def is_local_ip(ip):
    """Return True if the IP is a private/local network address."""
    return (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("172.16.") or ip.startswith("172.17.")
        or ip.startswith("172.18.") or ip.startswith("172.19.")
        or ip.startswith("172.2")   or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip == "255.255.255.255"
    )


def get_website(src_ip, dst_ip):
    """Look up the website name for a packet based on its IPs."""
    if dst_ip in ip_to_website:
        return ip_to_website[dst_ip]
    if src_ip in ip_to_website:
        return ip_to_website[src_ip]
    if is_local_ip(src_ip) and is_local_ip(dst_ip):
        return "Local Network"
    return "-"


def process_packet(packet):
    """Runs every time Scapy captures a packet."""
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    size = len(packet)
    time_now = datetime.now().strftime("%H:%M:%S")

    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    website = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        website = get_website(source_ip, destination_ip)

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        # If this is a DNS packet, learn the domain-to-IP mapping
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]

            # DNS Query (request going out)
            if packet.haslayer(DNSQR) and dns_layer.qr == 0:
                try:
                    domain = dns_layer.qd.qname.decode("utf-8").rstrip(".")
                    website = domain
                except Exception:
                    website = "-"

            # DNS Response (reply coming back) — remember IP→domain mapping
            elif dns_layer.qr == 1 and dns_layer.ancount > 0:
                try:
                    domain = dns_layer.qd.qname.decode("utf-8").rstrip(".")
                    website = domain
                    for i in range(dns_layer.ancount):
                        answer = dns_layer.an[i]
                        if isinstance(answer, DNSRR) and answer.type == 1:
                            ip_address = answer.rdata
                            if isinstance(ip_address, bytes):
                                ip_address = ip_address.decode("utf-8", errors="ignore")
                            ip_to_website[str(ip_address)] = domain
                except Exception:
                    website = "-"
            else:
                website = get_website(source_ip, destination_ip)
        else:
            website = get_website(source_ip, destination_ip)

    elif ICMP in packet:
        protocol = "ICMP"
        website = get_website(source_ip, destination_ip)

    if protocol == "OTHER":
        return

    packet_data = {
        "time": time_now,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "website": website,
        "size": size,
        "summary": packet.summary()
    }

    captured_packets.append(packet_data)


def should_stop(packet):
    return not is_capturing


def start_sniffing():
    global is_capturing
    is_capturing = True
    sniff(prn=process_packet, stop_filter=should_stop, store=False)


def stop_sniffing():
    global is_capturing
    is_capturing = False


def clear_packets():
    captured_packets.clear()
    ip_to_website.clear()
