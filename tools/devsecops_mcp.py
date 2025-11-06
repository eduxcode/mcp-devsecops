#!/usr/bin/env python3
import sys
from pathlib import Path
import json
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
        try:
            from PyPDF2 import PdfReader
        except Exception:
            return "[PyPDF2 não instalado — coloque o PDF em data/plano_de_trabalho/ ou instale PyPDF2 para extração automática]"

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
    # Coletar saídas rápidas dos scanners e montar um relatório estruturado
    findings = []
    metrics = {}
    summaries = {}

    # Plano de trabalho resumo
    summaries['executive_summary'] = read_plan()[:2000]

    # SAST quick
    try:
        sast_out = sast_check.run_bandit('.')
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SAST (Bandit) - Quick Scan',
            'description': sast_out[:4000],
            'recommendation': 'Reveja os achados do SAST e priorize correções críticas.',
            'tool': 'SAST',
            'location': str(Path('.').resolve())
        })
        metrics['sast_len'] = len(sast_out)
    except Exception as e:
        findings.append({
            'severity': 'LOW',
            'title': 'SAST (Bandit) - Falha ao rodar',
            'description': str(e),
            'recommendation': 'Verificar instalação do Bandit.',
            'tool': 'SAST',
            'location': ''
        })

    # Container quick (Trivy)
    try:
        checker = container_check.ContainerSecurityChecker()
        trivy_out = checker.trivy_scan_image('alpine:latest')
        findings.append({
            'severity': 'HIGH' if 'CRITICAL' in trivy_out or 'HIGH' in trivy_out else 'MEDIUM',
            'title': 'Container (Trivy) - Quick Scan',
            'description': trivy_out[:4000],
            'recommendation': 'Analise as vulnerabilidades e atualize imagens base.',
            'tool': 'Trivy',
            'location': 'alpine:latest'
        })
        metrics['trivy_len'] = len(trivy_out)
    except Exception as e:
        findings.append({
            'severity': 'LOW',
            'title': 'Trivy - Falha ao rodar',
            'description': str(e),
            'recommendation': 'Verificar instalação do Trivy.',
            'tool': 'Trivy',
            'location': ''
        })

    # DAST quick (se disponível)
    try:
        dast_sample = dast_check.run_zap_scan('http://localhost:8080')
        findings.append({
            'severity': 'MEDIUM',
            'title': 'DAST (ZAP) - Quick',
            'description': str(dast_sample)[:4000],
            'recommendation': 'Revisar resultados do DAST.',
            'tool': 'DAST',
            'location': 'http://localhost:8080'
        })
        metrics['dast_len'] = len(str(dast_sample))
    except Exception:
        # não interrompe se não houver alvo
        pass

    # Gerar relatório estruturado usando report_gen
    try:
        report = report_gen.create_report('Relatório Unificado - DevSecOps Assistant', findings, metrics, summaries, REPORT_DIR, locale='pt')
        print(f'Relatório gerado: {REPORT_DIR}')
    except Exception as e:
        print(f'Erro ao gerar relatório: {e}')

def analisar_arquivo(p):
    p = Path(p)
    if not p.exists():
        print(f"Arquivo não encontrado: {p}")
        return
    if p.suffix in [".yml", ".yaml", ".json"]:
        print(policy_check.analyze_config(p))
    elif p.name == "Dockerfile":
        checker = container_check.ContainerSecurityChecker()
        result = checker.analyze_dockerfile(str(p))
        print(checker.format_results(result))
    elif p.name == "docker-compose.yml" or p.name == "docker-compose.yaml":
        checker = container_check.ContainerSecurityChecker()
        result = checker.analyze_compose(str(p))
        print(checker.format_results(result))
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
                checker = container_check.ContainerSecurityChecker()
                print(checker.trivy_scan_image(target))
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
