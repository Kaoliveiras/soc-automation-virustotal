import os
from dotenv import load_dotenv
import requests
from pathlib import Path

# Isso garante que o Python ache o .env na mesma pasta deste arquivo
base_path = Path(__file__).resolve().parent
env_path = base_path / '.env'
load_dotenv(dotenv_path=env_path)

API_KEY = os.getenv("VT_API_KEY")


def check_ip(ip):
    # Verificação de segurança (Nunca envia a requisição sem a chave)
    if not API_KEY:
        print(f"[!] ERRO: Chave não encontrada em: {env_path}")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()[
                'data']['attributes']['last_analysis_stats']
            print(f"\n--- [ANÁLISE SOC] Resultado para {ip} ---")
            print(f"🔴 Maliciosos: {stats['malicious']}")
            print(f"🟢 Limpos: {stats['harmless']}")
        else:
            print(f"[!] Erro na API (Status {response.status_code}).")
    except Exception as e:
        print(f"[!] Erro de conexão: {e}")


if __name__ == "__main__":
    print("--- 🛡️ Scanner SOC Profissional ---")
    ip_alvo = input("Digite o IP para análise (ex: 8.8.8.8): ")
    check_ip(ip_alvo)
