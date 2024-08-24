from scapy.all import *
from analisador import analisar_pacote

def capturar_pacotes():
    print("Iniciando captura de pacotes...")
    sniff(prn=analisar_pacote, store=0, count=10)

if __name__ == "__main__":
    capturar_pacotes()
