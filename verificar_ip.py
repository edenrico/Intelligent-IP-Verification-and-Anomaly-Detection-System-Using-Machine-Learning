import requests

def verificar_ip_malicioso(ip):
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Authorization": "Bearer 5a2eef4e470be9"}  # Substitua pelo seu token real
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"Informações sobre o IP: {ip} - {data}")
    else:
        print(f"Falha ao consultar informações do IP: {ip}, Status Code: {response.status_code}")
