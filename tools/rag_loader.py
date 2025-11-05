#!/usr/bin/env python3
import os
import requests
from pathlib import Path
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

DATA_DIR = Path.home() / "projetos/devsecops/data/knowledge_base"
DB_DIR = Path.home() / "projetos/devsecops/chromadb"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

sources = {
    "owasp_top10": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/main/2021/OWASP_Top_10-2021.md",
    "owasp_api_top10": "https://raw.githubusercontent.com/OWASP/API-Security/main/2023/en/dist/owasp-api-top10-en.md",
    "nist_ssdf": "https://csrc.nist.gov/csrc/media/Publications/sp/800-218/final/documents/sp800-218.pdf",
    "cncf_whitepaper": "https://raw.githubusercontent.com/cncf/tag-security/main/security-whitepaper/v2/CNCF_security_whitepaper_v2.pdf",
}

def download_docs():
    for name, url in sources.items():
        file_path = DATA_DIR / f"{name}.pdf" if url.endswith(".pdf") else DATA_DIR / f"{name}.md"
        if not file_path.exists():
            print(f"Baixando {name}...")
            try:
                r = requests.get(url)
                with open(file_path, "wb") as f:
                    f.write(r.content)
            except Exception as e:
                print(f"Erro ao baixar {name}: {e}")

def build_index():
    texts = []
    for file in DATA_DIR.glob("*"):
        try:
            content = file.read_text(errors="ignore")
            texts.append(content)
        except Exception:
            pass

    splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=200)
    docs = splitter.create_documents(texts)

    embeddings = OllamaEmbeddings(model="llama3")
    db = Chroma.from_documents(docs, embeddings, persist_directory=str(DB_DIR))
    db.persist()
    print("✅ Base de conhecimento DevSecOps atualizada!")

if __name__ == "__main__":
    download_docs()
    build_index()
