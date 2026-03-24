import os
import requests
import time
from dotenv import load_dotenv
from pathlib import Path

# 1. Configuração de caminhos e variáveis de ambiente
base_path = Path(__file__).resolve().parent
env_path = base_path / '.env'
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv("VT_API_KEY")


def get_ip_reputation(ip_address):
    if not VT_API_KEY:
        print(f"[!] Erro: API Key não encontrada no arquivo .env")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()[
                'data']['attributes']['last_analysis_stats']
            print(
                f"[+] IP: {ip_address} | Malicioso: {stats['malicious']} | Inofensivo: {stats['harmless']}")
        elif response.status_code == 429:
            print(
                f"\n[!] Erro de Limite: Muitas requisições para o IP {ip_address}.")
        else:
            print(f"\n[!] Erro {response.status_code} para o IP {ip_address}")
    except Exception as e:
        print(f"\n[!] Erro de conexão: {e}")


if __name__ == "__main__":
    print("--- 🛡️ SOC AUTOMATION: Bulk IP Scanner ---")

    file_path = base_path / 'ips.txt'

    if not file_path.exists():
        print(f"[!] Erro: Arquivo 'ips.txt' não encontrado!")
    else:
        with open(file_path, 'r') as file:
            ip_list = [line.strip() for line in file if line.strip()]

        total_ips = len(ip_list)
        print(
            f"[*] Total de IPs encontrados: {total_ips}. Processando em lotes de 4...\n")

        for index, ip in enumerate(ip_list):
            get_ip_reputation(ip)

            # Lógica para esperar 60 segundos após cada 4 IPs
            if (index + 1) % 4 == 0 and index < total_ips - 1:
                print(
                    f"\n[!] Limite de 4 IPs atingido. Iniciando contagem regressiva...")

                # O Regressor de segundos (Countdown)
                for remaining in range(60, 0, -1):
                    # O '\r' faz o cronômetro atualizar na mesma linha
                    print(
                        f"--> Continuando em {remaining} segundos...   ", end="\r")
                    time.sleep(1)

                print("\n[!] Tempo esgotado! Retomando análise...\n")
            elif index < total_ips - 1:
                # Pequena pausa de segurança de 1 segundo entre IPs do mesmo lote
                time.sleep(1)

        print("\n[+] Análise finalizada com sucesso!")
