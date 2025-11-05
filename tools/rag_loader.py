#!/usr/bin/env python3
# Simple RAG loader: downloads a few official docs and saves to data/knowledge_base
import os, requests
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
KB = BASE / "data" / "knowledge_base"
KB.mkdir(parents=True, exist_ok=True)

sources = {
    "owasp_top10": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/main/2021/OWASP_Top_10-2021.md",
    "owasp_api_top10": "https://raw.githubusercontent.com/OWASP/API-Security/main/2023/en/dist/owasp-api-top10-en.md",
    "cncf_security_whitepaper": "https://raw.githubusercontent.com/cncf/tag-security/main/security-whitepaper/v2/CNCF_security_whitepaper_v2.pdf"
}

def download_all():
    for name, url in sources.items():
        out = KB / (name + (".pdf" if url.endswith('.pdf') else '.md'))
        if out.exists():
            print(f"Já existe: {out}")
            continue
        print(f"Baixando {name}...")
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            out.write_bytes(r.content)
            print(f"Salvo: {out}")
        except Exception as e:
            print(f"Erro ao baixar {url}: {e}")

if __name__ == '__main__':
    download_all()
    print("Pronto. Arquivos salvos em data/knowledge_base/")
