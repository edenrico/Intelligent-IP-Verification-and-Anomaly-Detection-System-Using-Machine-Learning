import joblib
import pandas as pd
from scapy.all import *
from verificar_ip import verificar_ip_malicioso
import ipaddress  #

# Carregar o modelo treinado
model = joblib.load('anomaly_detection_model.pkl')

# Carregar a ordem das colunas
with open('columns_order.txt', 'r') as f:
    columns_order = f.read().strip().split(',')

# Função para converter IP para inteiro
def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))

def analisar_pacote(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocolo = packet[IP].proto
        src_port = dst_port = icmp_type = icmp_code = -1

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code

        # Converter IPs para inteiros
        ip_src_int = ip_to_int(ip_src)
        ip_dst_int = ip_to_int(ip_dst)

        # Preparar dados para predição
        data = pd.DataFrame([[ip_src_int, ip_dst_int, protocolo, src_port, dst_port, icmp_type, icmp_code]],
                            columns=['ip_src', 'ip_dst', 'protocolo', 'src_port', 'dst_port', 'icmp_type', 'icmp_code'])

        # Garantir que todas as colunas dummy esperadas estejam presentes e na mesma ordem
        for col in columns_order:
            if col not in data.columns:
                data[col] = 0

        # Reordenar colunas para corresponder à ordem do treinamento
        data = data[columns_order]

        # Prever anomalia
        is_anomaly = model.predict(data)[0] == -1
        if is_anomaly:
            print(f"ALERTA: Tráfego anômalo detectado - IP Origem: {ip_src}, IP Destino: {ip_dst}, Protocolo: {protocolo}")
            verificar_ip_malicioso(ip_src)

        # processo de lógica
        from analisador import verificar_atividade_suspeita
        verificar_atividade_suspeita(packet, ip_src, ip_dst, protocolo, src_port, dst_port, icmp_type, icmp_code)

if __name__ == "__main__":
    sniff(prn=analisar_pacote)
