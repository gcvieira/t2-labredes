# Guilherme Vieira e Luigi Carvalho

import socket
import struct
import html
from datetime import datetime

# Cria um socket raw para usar como sniffer
def create_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    return sniffer

def parse_ethernet(data):
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", data[:14])
    return {
        "dest_mac": ":".join(format(b, "02x") for b in dest_mac),
        "src_mac": ":".join(format(b, "02x") for b in src_mac),
        "proto": socket.htons(proto),
    }, data[14:]

def parse_ip(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return {"src_ip": src_ip, "dest_ip": dest_ip, "protocol": ip_header[6]}, data[20:]

def parse_tcp(data):
    tcp_header = struct.unpack("!HHLLHHHH", data[:20])
    return {"src_port": tcp_header[0], "dest_port": tcp_header[1]}, data[20:]

def parse_udp(data):
    udp_header = struct.unpack("!HHHH", data[:8])
    return {"src_port": udp_header[0], "dest_port": udp_header[1]}, data[8:]

# Extrai pacotes HTTP
def extract_http(data):
    try:
        http_data = data.decode("utf-8", errors="ignore")
        if "Host:" in http_data:
            lines = http_data.split("\r\n")
            host = next(line.split(" ", 1)[1] for line in lines if line.startswith("Host:"))
            url = next(line.split(" ", 1)[1].split(" ")[0] for line in lines if line.startswith("GET"))
            return f"http://{host}{url}"
    except Exception:
        pass
    return None

# Extrai pacotes DNS
def extract_dns(data):
    try:
        query_name = []
        i = 12
        while data[i] != 0:
            length = data[i]
            query_name.append(data[i + 1:i + 1 + length].decode("utf-8"))
            i += length + 1
        return ".".join(query_name)
    except Exception:
        pass
    return None

# Salva o histórico em HTML
def save_history_to_html(history, filename="history.html"):
    with open(filename, "w") as file:
        file.write("<html><header><title>Historico de Navegacao</title></header><body><ul>")
        for entry in history:
            file.write(
                f'<li>{entry["timestamp"]} - {entry["src_ip"]} - <a href="{html.escape(entry["data"])}">{html.escape(entry["data"])}</a></li>'
            )
        file.write("</ul></body></html>")
    print(f"Historico salvo em {filename}")


def run_sniffer():
    sniffer = create_sniffer()
    history = []

    print("Sniffer iniciado. Pressione Ctrl+C para parar.")
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65536)
            eth, ip_data = parse_ethernet(raw_data)
            if eth["proto"] == 8:  # Protocolo IPv4
                ip, transport_data = parse_ip(ip_data)
                if ip["protocol"] == 6:  # TCP
                    tcp, app_data = parse_tcp(transport_data)
                    if tcp["dest_port"] == 80:  # HTTP
                        url = extract_http(app_data)
                        if url:
                            history.append({"timestamp": datetime.now(), "src_ip": ip["src_ip"], "data": url})
                            print(f"{ip['src_ip']} -> {url}")
                    elif tcp["dest_port"] == 443:  # HTTPs
                        url = extract_http(app_data)
                        if url:
                            history.append({"timestamp": datetime.now(), "src_ip": ip["src_ip"], "data": url})
                            print(f"{ip['src_ip']} -> {url}")
                elif ip["protocol"] == 17:  # UDP
                    udp, app_data = parse_udp(transport_data)
                    if udp["dest_port"] == 53:  # DNS
                        domain = extract_dns(app_data)
                        if domain:
                            history.append({"timestamp": datetime.now(), "src_ip": ip["src_ip"], "data": domain})
                            print(f"{ip['src_ip']} -> {domain}")
    except KeyboardInterrupt:
        save_history_to_html(history)

if __name__ == "__main__":
    run_sniffer()
