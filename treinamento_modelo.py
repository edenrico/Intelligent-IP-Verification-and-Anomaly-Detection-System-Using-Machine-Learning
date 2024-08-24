import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import ipaddress

# Função para converter IP para inteiro
def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))

# Carregar dados
data = pd.read_csv('network_traffic.csv', names=['ip_src', 'ip_dst', 'protocolo', 'src_port', 'dst_port', 'icmp_type', 'icmp_code'])

# Pré-processamento
data.fillna(-1, inplace=True)

# Converter IPs para inteiros
data['ip_src'] = data['ip_src'].apply(ip_to_int)
data['ip_dst'] = data['ip_dst'].apply(ip_to_int)

# Converter protocolo para string e depois para colunas dummies
data['protocolo'] = data['protocolo'].astype(str)
data = pd.get_dummies(data, columns=['protocolo'])

# Definir a ordem das colunas para garantir consistência
columns_order = data.columns.tolist()

# Treinamento do modelo
model = IsolationForest(n_estimators=100, contamination=0.1)
model.fit(data)

# Salvar o modelo
joblib.dump(model, 'anomaly_detection_model.pkl')

# Salvar a ordem das colunas para referência futura
with open('columns_order.txt', 'w') as f:
    f.write(','.join(columns_order))
