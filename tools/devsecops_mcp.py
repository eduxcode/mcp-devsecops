#!/usr/bin/env python3
import sys
from pathlib import Path
import json
from PyPDF2 import PdfReader
from tools import sast_check, sca_check, dast_check, container_check, policy_check, monitoring_check, report_gen
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings
from langchain.prompts import PromptTemplate
from langchain.chains import RetrievalQA
# Basic paths
BASE = Path(__file__).resolve().parents[1]
PLAN = BASE / "data" / "plano_de_trabalho" / "Plano_DevSecOps.pdf"
REPORT_DIR = BASE / "relatorios"
DB_DIR = Path.home() / "projetos/devsecops/chromadb"
REPORT_DIR.mkdir(exist_ok=True)

def read_plan():
    if not PLAN.exists():
        return "[PDF do plano não encontrado. Coloque em data/plano_de_trabalho/]"
    try:
        reader = PdfReader(str(PLAN))
        text = ""
        for p in reader.pages:
            t = p.extract_text()
            if t:
                text += t + "\n"
        return text
    except Exception as e:
        return f"[Erro lendo PDF: {e}]"

def gerar_relatorio():
    parts = []
    parts.append("# Relatório Unificado - DevSecOps Assistant\n")
    parts.append("## Plano de Trabalho (resumo)\n")
    parts.append(read_plan()[:4000] + "\n")
    # Run quick scans if modules available
    parts.append("## SAST (Bandit - quick)\n")
    parts.append(sast_check.run_bandit(".")[:8000])
    parts.append("## Container (Trivy quick)\n")
    parts.append(container_check.trivy_scan_image("alpine:latest")[:8000])
    path = REPORT_DIR / "relatorio_unificado.md"
    path.write_text("\n\n".join(parts), encoding="utf-8")
    print(f"Relatório gerado: {path}")

def analisar_arquivo(p):
    p = Path(p)
    if not p.exists():
        print(f"Arquivo não encontrado: {p}")
        return
    if p.suffix in [".yml", ".yaml"]:
        print(policy_check.analyze_yaml(p))
    elif p.name == "Dockerfile":
        print(container_check.analyze_dockerfile(p))
    elif p.suffix == ".rego":
        print(policy_check.analyze_rego(p))
    else:
        print("Tipo de arquivo não suportado para análise rápida.")

def contextual_answer(query):
    embeddings = OllamaEmbeddings(model="llama3")
    db = Chroma(persist_directory=str(DB_DIR), embedding_function=embeddings)
    retriever = db.as_retriever(search_kwargs={"k": 3})

    qa_chain = RetrievalQA.from_chain_type(
        llm=None,  # o Continue/Ollama já fornece o LLM ativo
        chain_type="stuff",
        retriever=retriever,
        return_source_documents=True
    )
    result = qa_chain({"query": query})
    return result["result"]

def main():
    if len(sys.argv) < 2:
        print("Uso: python devsecops_mcp.py <acao> [args]")
        print("Ações: ler-plano, gerar-relatorio, analisar <arquivo>, scan <tool> <target>, perguntar <query>")
        return
    cmd = sys.argv[1]
    if cmd == "ler-plano":
        print(read_plan()[:8000])
    elif cmd == "gerar-relatorio":
        gerar_relatorio()
    elif cmd == "analisar":
        if len(sys.argv) < 3:
            print("Forneça o arquivo a analisar.")
        else:
            analisar_arquivo(sys.argv[2])
    elif cmd == "scan":
        if len(sys.argv) < 4:
            print("Uso: scan <sast|container|dast> <target>")
        else:
            tool = sys.argv[2]
            target = sys.argv[3]
            if tool == "sast":
                print(sast_check.run_bandit(target if len(sys.argv) > 3 else "."))
            elif tool == "container":
                print(container_check.trivy_scan(target))
            elif tool == "dast":
                print(dast_check.run_zap_scan(target))
            else:
                print("Tool desconhecida.")
    elif cmd == "perguntar":
        if len(sys.argv) < 3:
            print("Forneça uma pergunta para o assistente.")
        else:
            query = " ".join(sys.argv[2:])
            try:
                resposta = contextual_answer(query)
                print(resposta)
            except Exception as e:
                print(f"Erro ao processar a pergunta: {e}")
    else:
        print("Comando não reconhecido.")

if __name__ == '__main__':
    main()
