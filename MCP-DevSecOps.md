# 🧠 **MCP DevSecOps Assistant — Guia Completo**

## 🧩 **Sobre o projeto**
O **MCP DevSecOps Assistant** é um agente local (Model Context Protocol) projetado para **auxiliar no desenvolvimento e gestão de pipelines DevSecOps End-to-End** de forma **segura, autônoma e independente da aplicação principal**.

⚙️ Ele foi desenvolvido para:
- Acompanhar o residente em todas as fases do projeto DevSecOps;
- Executar análises automatizadas (SAST, SCA, DAST, Containers, Políticas, APIs);
- Gerar relatórios técnicos e executivos com base em normas oficiais (NIST, OWASP, CNCF);
- Oferecer recomendações baseadas em práticas de segurança open-source;
- Funcionar **localmente**, garantindo **segurança, privacidade e compliance institucional**.

---

## 🛡️ **Nota importante sobre uso local e compliance**
Este MCP roda **somente no ambiente local do desenvolvedor** (Linux, macOS ou Windows).  
Ele **não interfere diretamente no código-fonte, repositórios ou pipelines da instituição**, garantindo:

- **Isolamento total do ambiente institucional**  
- **Conformidade com políticas de segurança e sigilo de dados**  
- **Autonomia e liberdade técnica** para o residente trabalhar com segurança  
- **Zero impacto no código-fonte da aplicação real**

> 🧩 O MCP atua como uma **ferramenta de apoio técnico**, e não como parte da aplicação que você está desenvolvendo.  
> Ele serve para **analisar, sugerir, documentar e simular**, mas **não altera nem executa nada diretamente nos repositórios oficiais.**

---

## 🧱 **Arquitetura geral**

```
┌──────────────────────────────┐
│ VSCode + Continue.dev        │  ← Interface interativa
└──────────────┬───────────────┘
               │
      ┌────────▼────────┐
      │ MCP DevSecOps   │  ← (Python + LangChain + RAG)
      │ tools/devsecops_mcp.py │
      └────────┬────────┘
               │
 ┌─────────────▼───────────────────────────┐
 │  Módulos técnicos (Bandit, ZAP, Trivy)  │
 │  + Base RAG (OWASP, NIST, CNCF)         │
 └─────────────────────────────────────────┘
               │
        ┌──────▼──────┐
        │  Ollama     │ ← IA local (Llama3)
        │  Gemini API │ ← (opcional)
        └─────────────┘
```

---

# ⚙️ **1. Instalação**

## 🐧 **Ubuntu / Debian / WSL**
```bash
git clone https://github.com/seu-repositorio/mcp-devsecops.git
cd mcp-devsecops
chmod +x install.sh
./install.sh
```
> 💡 Após instalar, reinicie o terminal e execute:
```bash
ollama pull llama3
```

---

## 🍎 **macOS (Intel ou M1/M2)**
```bash
git clone https://github.com/seu-repositorio/mcp-devsecops.git
cd mcp-devsecops
chmod +x install.sh
./install.sh
```
Instale manualmente:
- [Docker Desktop](https://www.docker.com/get-started)
- [Ollama](https://ollama.com/download)

---

## 🪟 **Windows 10/11**
1. Instale:
   - [Docker Desktop](https://www.docker.com/get-started)
   - [Python 3.10+](https://www.python.org/downloads/)
   - [Git](https://git-scm.com/downloads)
   - [Ollama (opcional)](https://ollama.com/download)
2. Clone o projeto:
   ```powershell
   git clone https://github.com/seu-repositorio/mcp-devsecops.git
   cd mcp-devsecops
   ```
3. Execute:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\install.ps1
   ```

---

# 📚 **2. Preparação do ambiente**

1️⃣ Coloque o PDF do seu **plano de trabalho** em:
```
data/plano_de_trabalho/Plano_DevSecOps.pdf
```

2️⃣ Crie a base de conhecimento (RAG):
```bash
python tools/rag_loader.py
```
> Isso baixa e indexa documentos oficiais (OWASP, NIST, CNCF).

3️⃣ Configure o VSCode com o plugin [Continue.dev](https://marketplace.visualstudio.com/items?itemName=Continue.continue).  
O arquivo `.continue/config.json` já está preparado.

---

# 🚀 **3. Uso prático**

## ✅ **Comandos principais**

| Ação | Comando | Descrição |
|------|----------|-----------|
| Ler plano | `python tools/devsecops_mcp.py ler-plano` | Lê o PDF do plano |
| Gerar relatório | `python tools/devsecops_mcp.py gerar-relatorio` | Gera relatório técnico |
| Analisar arquivo | `python tools/devsecops_mcp.py analisar <arquivo>` | Avalia YAML, Dockerfile, Rego |
| Rodar scan | `python tools/devsecops_mcp.py scan <sast|dast|container> <target>` | Executa varredura específica |

---

# 🔍 **4. Exemplos por módulo**

### 🔹 SAST — Análise Estática
```bash
python tools/devsecops_mcp.py scan sast ./src
```
> Varredura com Bandit.  

---

### 🔹 SCA — Dependências
```bash
docker run --rm -v $(pwd):/src owasp/dependency-check --project MyApp --scan /src
```

---

### 🔹 DAST — Teste Dinâmico (OWASP ZAP)
```bash
python tools/devsecops_mcp.py scan dast http://localhost:8080
```

---

### 🔹 Containers — Segurança de Imagens (Trivy)
```bash
python tools/devsecops_mcp.py scan container myapp:latest
```

---

### 🔹 Políticas — Kubernetes / OPA / Kyverno
```bash
python tools/devsecops_mcp.py analisar kubernetes/policies/limit-cpu.yaml
```

---

### 🔹 Monitoramento — Prometheus / ELK
*(placeholder – expansão futura)*  
Valida configuração básica:
```bash
python -c "from tools.monitoring_check import check_prometheus_config; print(check_prometheus_config('prometheus.yml'))"
```

---

# 🧾 **5. Geração de Relatórios**
```bash
python tools/devsecops_mcp.py gerar-relatorio
```
> Gera `relatorios/relatorio_unificado.md` com:
> - Resumo do plano  
> - Resultados SAST/Container  
> - Recomendações automáticas  

---

# 🧩 **6. Integração com Continue.dev**
Com o Continue instalado no VSCode:
```
> MCP: Analisar pipeline GitLab
> MCP: Gerar relatório DevSecOps
> MCP: Explicar o NIST SSDF nesta aplicação
```
O Continue chama o MCP local, que consulta sua base RAG (OWASP, NIST, CNCF) e responde contextualizado.

---

# ⚡ **7. Dicas rápidas**

| Problema | Solução |
|-----------|----------|
| Trivy/ZAP não encontrados | `docker pull aquasec/trivy` e `docker pull owasp/zap2docker-stable` |
| Relatório vazio | Verifique o PDF do plano |
| Ollama inativo | `ollama serve` ou `ollama run llama3` |
| Erros de permissão | `sudo usermod -aG docker $USER && newgrp docker` |
| Execução lenta | Ajuste `timeout` nos scripts em `tools/` |

---

# 🔮 **8. Expansões futuras**
- SOAR open-source (TheHive / Shuffle)
- Relatórios PDF automáticos
- Dashboards Grafana + Prometheus
- Políticas Kyverno/OPA automáticas
- Métricas OWASP SAMM (maturidade DevSecOps)

---

# 🧾 **9. Créditos e Conformidade**
📘 Desenvolvido por **Davi Soares**  
Residênte em **DevSecOps — RNP (Pipeline End-to-End com Ferramentas Open-Source)**  

Normas aplicadas:
- **NIST SP 800-218** — Secure Software Development Framework  
- **OWASP Top 10** & **OWASP API Security Top 10**  
- **CNCF Security Whitepaper v2**  
- **OWASP SAMM**  

> ⚙️ **Este MCP é uma ferramenta auxiliar de análise e aprendizado DevSecOps.**  
> Ele opera **localmente por motivos de segurança e compliance**, **não interagindo nem modificando diretamente** as aplicações ou pipelines da instituição.
