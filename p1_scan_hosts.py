# Guilherme Vieira e Luigi Carvalho

import socket
import struct
import time
import ipaddress
import sys

# Calcula o checksum para ICMP
def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    for count in range(0, count_to, 2):
        this = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this
        sum = sum & 0xffffffff
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    return ~sum & 0xffff

# Envia ICMP Echo Request e retorna o tempo de resposta
def send_ping(sock, addr, timeout):
    icmp_type = 8
    icmp_code = 0
    packet_id = int((id(timeout) * time.time()) % 65535)
    seq_number = 1
    checksum_placeholder = 0

    # Estrutura ICMP
    header = struct.pack('bbHHh', icmp_type, icmp_code, checksum_placeholder, packet_id, seq_number)
    data = struct.pack('d', time.time())
    checksum_value = checksum(header + data)

    # Reconstroi o pacote com checksum correto
    header = struct.pack('bbHHh', icmp_type, icmp_code, checksum_value, packet_id, seq_number)
    packet = header + data

    start_time = time.time()
    sock.sendto(packet, (addr, 1))
    sock.settimeout(timeout / 1000.0)

    try:
        data, _ = sock.recvfrom(1024)
        end_time = time.time()
        return (end_time - start_time) * 1000
    except socket.timeout:
        return None

def scan_network(network, timeout):
    active_hosts = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    for ip in network:
        delay = send_ping(sock, str(ip), timeout)
        if delay is not None:
            active_hosts.append((str(ip), delay))

    sock.close()
    return active_hosts

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python scan_hosts.py <rede/máscara> <timeout_ms>")
        sys.exit(1)

    network = ipaddress.ip_network(sys.argv[1], strict=False)
    timeout = int(sys.argv[2])
    total_hosts = network.num_addresses - 2 # Exclui rede e broadcast
    start_scan = time.time()

    active_hosts = scan_network(network.hosts(), timeout)
    end_scan = time.time()

    # Resultados
    print(f"Numero de maquinas ativas: {len(active_hosts)}")
    print(f"Numero total de maquinas: {total_hosts}")
    print(f"Tempo total de varredura: {end_scan - start_scan:.2f} segundos")

    for ip, delay in active_hosts:
        print(f"{ip} respondeu em {delay:.2f} ms")
