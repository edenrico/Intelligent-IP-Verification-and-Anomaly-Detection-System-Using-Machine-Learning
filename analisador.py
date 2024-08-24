import csv
from scapy.all import *
from verificar_ip import verificar_ip_malicioso

def analisar_pacote(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocolo = packet[IP].proto
        src_port = dst_port = icmp_type = icmp_code = None

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code

        with open('network_traffic.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([ip_src, ip_dst, protocolo, src_port, dst_port, icmp_type, icmp_code])
            
        verificar_atividade_suspeita(packet, ip_src, ip_dst, protocolo, src_port, dst_port, icmp_type, icmp_code)

def verificar_atividade_suspeita(packet, ip_src, ip_dst, protocolo, src_port, dst_port, icmp_type, icmp_code):
    if TCP in packet:
        print(f"IP Origem: {ip_src}, IP Destino: {ip_dst}, Protocolo: TCP, Porta Origem: {src_port}, Porta Destino: {dst_port}")
        if dst_port in [21, 22, 23, 80, 443]:
            print(f"ALERTA: Possível varredura de portas TCP - IP Origem: {ip_src}, IP Destino: {ip_dst}, Porta Destino: {dst_port}")
            verificar_ip_malicioso(ip_src)
    elif UDP in packet:
        print(f"IP Origem: {ip_src}, IP Destino: {ip_dst}, Protocolo: UDP, Porta Origem: {src_port}, Porta Destino: {dst_port}")
        if dst_port != 53 and src_port > 1024:
            print(f"ALERTA: Tráfego UDP incomum - IP Origem: {ip_src}, IP Destino: {ip_dst}, Porta Origem: {src_port}, Porta Destino: {dst_port}")
            verificar_ip_malicioso(ip_src)
    elif ICMP in packet:
        print(f"IP Origem: {ip_src}, IP Destino: {ip_dst}, Protocolo: ICMP, Tipo ICMP: {icmp_type}, Código ICMP: {icmp_code}")
        if icmp_type == 8:
            print(f"ALERTA: Ping de morte detectado - IP Origem: {ip_src}, IP Destino: {ip_dst}")
            verificar_ip_malicioso(ip_src)
    else:
        print(f"IP Origem: {ip_src}, IP Destino: {ip_dst}, Protocolo: {protocolo}")
